# ==========================================
# 1. IMPORTS
# ==========================================
import os
import json
import logging
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

import razorpay
import firebase_admin
from firebase_admin import credentials, firestore, auth as firebase_auth

from fpdf import FPDF
import io
from flask import send_file

# Load environment variables from the .env file
load_dotenv()

# ==========================================
# 2. CONFIGURATION & LOGGING SETUP
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("jambawear_api")

app = Flask(__name__)

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
CORS(app, resources={r"/*": {"origins": ALLOWED_ORIGINS}})

ALLOWED_ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "jamba4334@gmail.com")

# ==========================================
# 3. INITIALIZE SERVICES
# ==========================================
FIREBASE_CONFIG_STR = os.getenv("FIREBASE_CONFIG")

try:
    if not firebase_admin._apps:
        if FIREBASE_CONFIG_STR:
            cred_dict = json.loads(FIREBASE_CONFIG_STR)
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred)
        else:
            logger.error("❌ FIREBASE_CONFIG is missing from .env variables.")
            
    if firebase_admin._apps:
        db = firestore.client()
        logger.info("✅ Firebase initialized successfully.")
    else:
        db = None
except Exception as e:
    logger.error(f"❌ Firebase initialization failed: {e}")
    db = None

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")

try:
    if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
        razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
        logger.info("✅ Razorpay client initialized.")
    else:
        logger.warning("⚠️ Razorpay keys missing. Payment gateway disabled.")
        razorpay_client = None
except Exception as e:
    logger.error(f"❌ Razorpay initialization failed: {e}")
    razorpay_client = None

# ==========================================
# 4. SECURITY MIDDLEWARE (ADMIN & SELLER)
# ==========================================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Unauthorized: Missing token"}), 401
        
        token = auth_header.split(" ")[1]
        try:
            decoded_token = firebase_auth.verify_id_token(token)
            email = decoded_token.get("email")
            
            if email == ALLOWED_ADMIN_EMAIL:
                return f(*args, **kwargs)

            if db is not None:
                admin_query = db.collection("admin_users").where("email", "==", email).limit(1).get()
                if len(admin_query) > 0:
                    admin_data = admin_query[0].to_dict()
                    if admin_data.get("isAuthorized") == True:
                        return f(*args, **kwargs)

            return jsonify({"error": "Forbidden: Insufficient permissions"}), 403

        except Exception as e:
            return jsonify({"error": "Unauthorized: Invalid or expired token"}), 401
            
        return f(*args, **kwargs)
    return decorated_function

def seller_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        
        token = auth_header.split(" ")[1]
        try:
            decoded_token = firebase_auth.verify_id_token(token)
            email = decoded_token.get("email")
            if not email:
                return jsonify({"error": "Invalid token payload"}), 401
            
            seller_doc = db.collection("authorized_sellers").document(email).get()
            if not seller_doc.exists:
                return jsonify({"error": "Forbidden: Seller account not found"}), 403
                
            request.seller_email = email
        except Exception as e:
            return jsonify({"error": "Unauthorized: Invalid token"}), 401
            
        return f(*args, **kwargs)
    return decorated_function

# ==========================================
# 5. PUBLIC ROUTES (Customer Facing)
# ==========================================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"server": "running", "status": "ok"}), 200

@app.route("/create-order", methods=["POST"])
def create_order():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        data = request.get_json()
        cart = data.get("cart", [])
        customer_email = data.get("customer", "guest@jambawear.com")
        shipping_address = data.get("shippingAddress", {})
        payment_method = data.get("payment_method", "Razorpay")
        promo_code_str = data.get("promo_code", "").strip().upper()

        secure_subtotal = 0
        enriched_cart = []
        seller_emails_set = set()

        # 1. VERIFY PROMO CODE
        promo_data = None
        if promo_code_str:
            promo_query = db.collection("promocodes").where("code", "==", promo_code_str).where("status", "==", "active").limit(1).get()
            if promo_query:
                temp_promo = promo_query[0].to_dict()
                
                # FIXED TIMEZONE CHECK
                now = datetime.now(timezone.utc).isoformat()
                
                is_valid_time = True
                if temp_promo.get("valid_from"):
                    promo_start = temp_promo.get("valid_from")
                    if not promo_start.endswith("Z") and "+" not in promo_start:
                        promo_start += "+05:30"  # Force IST if naive
                    if now < promo_start: is_valid_time = False
                        
                if temp_promo.get("valid_until"):
                    promo_end = temp_promo.get("valid_until")
                    if not promo_end.endswith("Z") and "+" not in promo_end:
                        promo_end += "+05:30" # Force IST if naive
                    if now > promo_end: is_valid_time = False
                
                is_valid_usage = True
                if temp_promo.get("usage_limit") == "single" and customer_email in temp_promo.get("used_by", []): is_valid_usage = False
                
                # STRICT PAYMENT METHOD ENFORCEMENT
                promo_payment_method = temp_promo.get("applicable_payment_method", "all")
                if promo_payment_method == "online" and payment_method.upper() == "COD":
                    return jsonify({"error": "This promo code is strictly for Prepaid Online Orders."}), 400
                if promo_payment_method == "cod" and payment_method.upper() != "COD":
                    return jsonify({"error": "This promo code is only valid for Cash on Delivery orders."}), 400

                if is_valid_time and is_valid_usage:
                    promo_data = temp_promo
                    promo_doc_id = promo_query[0].id

        # 2. PROCESS CART & ISOLATE DISCOUNTS PER BRAND
        total_discount = 0
        seller_eligible_subtotal = 0

        for item in cart:
            item_id = str(item.get("id"))
            quantity = int(item.get("quantity", 1))
            
            doc_ref = db.collection("products").document(item_id).get()
            if not doc_ref.exists:
                query = db.collection("products").where("item_id", "==", item_id).limit(1).get()
                if not query: return jsonify({"error": f"Product {item_id} out of stock."}), 400
                product = query[0].to_dict()
            else:
                product = doc_ref.to_dict()

            real_price = float(product.get("selling_price", 0))
            item_total = real_price * quantity
            secure_subtotal += item_total
            
            seller_email = product.get("sellerEmail", "")
            if seller_email: seller_emails_set.add(seller_email)
            
            is_returnable = product.get("isReturnable", True)

            # Check if this item belongs to the seller who made the promo code
            if promo_data and promo_data.get("creator_role") == "seller":
                if promo_data.get("seller_email") == seller_email:
                    seller_eligible_subtotal += item_total

            item.update({
                "price": real_price,
                "brandName": product.get("brandName", ""),
                "sellerName": product.get("sellerName", ""),
                "sellerEmail": seller_email,
                "isReturnable": is_returnable
            })
            enriched_cart.append(item)

        # 3. CALCULATE FINAL MATH
        if promo_data:
            discount_value = float(promo_data.get("value", 0))
            
            if promo_data.get("creator_role") == "admin":
                if promo_data.get("type") == "percentage":
                    total_discount = secure_subtotal * (discount_value / 100)
                else:
                    total_discount = min(discount_value, secure_subtotal)
            
            elif promo_data.get("creator_role") == "seller":
                if promo_data.get("type") == "percentage":
                    total_discount = seller_eligible_subtotal * (discount_value / 100)
                else:
                    total_discount = min(discount_value, seller_eligible_subtotal)

        # --- GST CALCULATION (Applied to the post-discount taxable value) ---
        taxable_value = secure_subtotal - total_discount
        
        # Apparel GST Rule: 5% if below 2500, 18% if above
        if taxable_value <= 2500:
            total_gst = taxable_value * 0.05
        else:
            total_gst = taxable_value * 0.18

        shipping_fee = 149 if secure_subtotal < 1999 else 0
        final_total = max(taxable_value + shipping_fee, 0)
        unique_jamba_id = "JB" + datetime.now(timezone.utc).strftime("%y%m%d%H%M%S")

        order_data = {
            "jamba_order_id": unique_jamba_id,
            "email": customer_email,
            "items": enriched_cart,
            "subtotal": secure_subtotal,
            "discount_applied": total_discount,
            "promo_used": promo_code_str if total_discount > 0 else None,
            "promo_creator_role": promo_data.get("creator_role") if promo_data else None,
            "promo_seller_email": promo_data.get("seller_email") if promo_data else None,
            "taxable_value": taxable_value,
            "total_gst": total_gst,
            "shipping_fee": shipping_fee,
            "total": final_total,
            "status": "pending",
            "payment_method": payment_method,
            "shippingAddress": shipping_address,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "sellerEmails": list(seller_emails_set)
        }

        if total_discount > 0 and promo_data and promo_data.get("usage_limit") == "single":
            db.collection("promocodes").document(promo_doc_id).update({
                "used_by": firestore.ArrayUnion([customer_email])
            })

        if payment_method == "COD":
            # FIXED: Set status to processing for COD so it doesn't get hidden as abandoned
            order_data["status"] = "processing"
            order_data["order_id"] = f"cod_{int(datetime.now().timestamp())}"
            db.collection("orders").add(order_data)
            return jsonify({"status": "success", "payment_method": "COD", "order_id": order_data["jamba_order_id"]}), 201

        if not razorpay_client: return jsonify({"error": "Payment gateway unavailable"}), 503

        razorpay_order = razorpay_client.order.create({
            "amount": int(final_total * 100),
            "currency": "INR",
            "receipt": f"rcpt_{int(datetime.now().timestamp())}"
        })
        order_data["razorpay_order_id"] = razorpay_order["id"]
        db.collection("orders").add(order_data)
        
        return jsonify(razorpay_order), 201
    except Exception as e:
        return jsonify({"error": "Failed to process order"}), 500

@app.route("/verify-payment", methods=["POST"])
def verify_payment():
    if db is None: return jsonify({"error": "Firebase is not connected."}), 500
    if not razorpay_client: return jsonify({"error": "Razorpay is not configured."}), 500
    try:
        data = request.get_json()
        razorpay_order_id = data.get("razorpay_order_id")
        rose_payment_id = data.get("razorpay_payment_id")
        razorpay_signature = data.get("razorpay_signature")

        razorpay_client.utility.verify_payment_signature({
            "razorpay_order_id": razorpay_order_id,
            "razorpay_payment_id": rose_payment_id,
            "razorpay_signature": razorpay_signature,
        })

        orders_ref = db.collection("orders").where("razorpay_order_id", "==", razorpay_order_id).limit(1).get()
        if len(orders_ref) > 0:
            doc_id = orders_ref[0].id
            db.collection("orders").document(doc_id).update({
                "status": "paid",
                "payment_id": rose_payment_id,
            })
        return jsonify({"status": "Payment verified and saved!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# 6. ADMIN ROUTES
# ==========================================
@app.route("/admin/products", methods=["GET", "POST"])
@admin_required
def admin_products():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    if request.method == "GET":
        try:
            limit = int(request.args.get("limit", 50))
            products = []
            docs = db.collection("products").order_by("created_at", direction=firestore.Query.DESCENDING).limit(limit).get()
            for doc in docs: products.append({**doc.to_dict(), "docId": doc.id})
            return jsonify(products), 200
        except Exception as e: 
            return jsonify({"error": str(e)}), 500
    if request.method == "POST":
        try:
            data = request.get_json()
            data["created_at"] = datetime.now(timezone.utc).isoformat()
            _, doc_ref = db.collection("products").add(data)
            return jsonify({"status": "success", "id": doc_ref.id}), 201
        except Exception as e: 
            return jsonify({"error": str(e)}), 500

@app.route("/admin/products/<doc_id>", methods=["PUT", "DELETE"])
@admin_required
def admin_product_detail(doc_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        doc_ref = db.collection("products").document(doc_id)
        if request.method == "PUT":
            doc_ref.update(request.get_json())
            return jsonify({"status": "success"}), 200
        if request.method == "DELETE":
            doc_ref.delete()
            return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/orders", methods=["GET"])
@admin_required
def admin_orders():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        limit = int(request.args.get("limit", 50))
        orders = []
        docs = db.collection("orders").order_by("created_at", direction=firestore.Query.DESCENDING).limit(limit).get()
        for doc in docs: orders.append({**doc.to_dict(), "id": doc.id})
        return jsonify(orders), 200
    except Exception as e: 
        return jsonify({"error": str(e)}), 500

@app.route("/admin/orders/<order_id>", methods=["PUT"])
@admin_required
def update_order(order_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        db.collection("orders").document(order_id).update(request.get_json())
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/orders/<order_id>/force-clear", methods=["POST"])
@admin_required
def force_clear_order(order_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        db.collection("orders").document(order_id).update({"status": "settled_override"})
        return jsonify({"status": "success", "message": "Escrow released manually."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/customers", methods=["GET"])
@admin_required
def admin_customers():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        limit = int(request.args.get("limit", 50))
        customers = [{**doc.to_dict(), "id": doc.id} for doc in db.collection("users").limit(limit).get()]
        return jsonify(customers), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/settings/<doc_id>", methods=["GET", "PUT"])
@admin_required
def admin_settings(doc_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        if request.method == "GET":
            doc = db.collection("settings").document(doc_id).get()
            if doc.exists: return jsonify(doc.to_dict()), 200
            return jsonify({"tribes": []} if doc_id == "tribe_categories" else {}), 200
        if request.method == "PUT":
            data = request.get_json()
            if doc_id == "tribe_categories": data["last_updated"] = datetime.now(timezone.utc).isoformat()
            db.collection("settings").document(doc_id).set(data, merge=True)
            return jsonify({"status": "Settings updated"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/sellers", methods=["GET", "POST"])
@admin_required
def admin_sellers():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        if request.method == "GET":
            sellers = []
            for doc in db.collection("authorized_sellers").get():
                seller_data = {**doc.to_dict(), "id": doc.id}
                prof_doc = db.collection("seller_profiles").document(doc.id).get()
                seller_data["profile"] = prof_doc.to_dict() if prof_doc.exists else {}
                sellers.append(seller_data)
            return jsonify(sellers), 200
            
        if request.method == "POST":
            email = request.get_json().get("email")
            db.collection("authorized_sellers").document(email).set({
                "email": email, "addedAt": datetime.now(timezone.utc).isoformat(), "addedBy": ALLOWED_ADMIN_EMAIL
            })
            return jsonify({"status": "Seller authorized"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/sellers/<email>", methods=["DELETE"])
@admin_required
def remove_seller(email):
    try:
        db.collection("authorized_sellers").document(email).delete()
        return jsonify({"status": "Seller removed"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/seller_profiles/<email>", methods=["GET", "PUT"])
@admin_required
def admin_seller_profile(email):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        if request.method == "GET":
            doc = db.collection("seller_profiles").document(email).get()
            return jsonify(doc.to_dict() if doc.exists else {}), 200
            
        if request.method == "PUT":
            data = request.get_json()
            data["updated_at"] = datetime.now(timezone.utc).isoformat()
            db.collection("seller_profiles").document(email).set(data, merge=True)
            return jsonify({"status": "Profile updated"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# 7. ADMIN FINANCE & LEDGERS
# ==========================================
@app.route("/admin/payouts", methods=["GET"])
@admin_required
def admin_payouts():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        status_filter = request.args.get("status")
        email_filter = request.args.get("email")
        
        query = db.collection("payout_requests")
        if status_filter: 
            query = query.where("status", "==", status_filter)
        if email_filter:
            query = query.where("email", "==", email_filter)
            
        payouts = [{**doc.to_dict(), "id": doc.id} for doc in query.get()]
        return jsonify(payouts), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/finance/customer-payments", methods=["GET"])
@admin_required
def admin_customer_payments():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        limit = int(request.args.get("limit", 100))
        docs = db.collection("orders").order_by("created_at", direction=firestore.Query.DESCENDING).limit(limit).get()
        payments = []
        for doc in docs:
            order = doc.to_dict()
            raw_method = order.get("payment_method", "Online")
            payments.append({
                "id": doc.id,
                "order_id": order.get("jamba_order_id", "N/A"),
                "customer": order.get("email", "Guest"),
                "amount": order.get("total", 0),
                "method": "COD" if raw_method.upper() == "COD" else "Online",
                "status": order.get("status", "pending"),
                "date": datetime.fromisoformat(order.get("created_at")).strftime("%d %b %Y") if order.get("created_at") else "Unknown"
            })
        return jsonify(payments), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/finance/kpis", methods=["GET"])
@admin_required
def admin_finance_kpis():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        payouts_query = db.collection("payout_requests").where("status", "==", "pending").get()
        pending_payouts = sum([float(doc.to_dict().get("amount", doc.to_dict().get("netPayable", 0))) for doc in payouts_query])

        orders_query = db.collection("orders").where("status", "==", "paid").get()
        in_escrow = sum([float(doc.to_dict().get("total", 0)) for doc in orders_query])

        settled_query = db.collection("payout_requests").where("status", "==", "paid").get()
        jamba_revenue = sum([float(doc.to_dict().get("jambaFee", 0)) for doc in settled_query])
        
        return jsonify({
            "jambaRevenue": round(jamba_revenue, 2),
            "pendingPayouts": round(pending_payouts, 2),
            "inEscrow": round(in_escrow, 2),
            "totalGST": round(jamba_revenue * 0.18, 2)
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/transactions", methods=["GET"])
@admin_required
def admin_transactions():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        limit = int(request.args.get("limit", 100))
        docs = db.collection("transactions").order_by("created_at", direction=firestore.Query.DESCENDING).limit(limit).get()
        return jsonify([{**doc.to_dict(), "id": doc.id} for doc in docs]), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/finance/adjust", methods=["POST"])
@admin_required
def inject_financial_adjustment():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        data = request.get_json()
        brand = data.get("brand", "Global Correction")
        amount = float(data.get("amount", 0))
        db.collection("transactions").add({
            "txId": f"ADJ-{int(datetime.now(timezone.utc).timestamp())}",
            "date": datetime.now(timezone.utc).strftime("%d %b %Y"),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "type": "Bonus" if amount >= 0 else "Penalty",
            "brand": brand,
            "amount": f"+ ₹{amount}" if amount >= 0 else f"- ₹{abs(amount)}",
            "status": f"Applied: {data.get('reason', 'Force Adj')}"
        })
        return jsonify({"status": "success"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/payouts/<payout_id>", methods=["PUT"])
@admin_required
def update_payout(payout_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        data = request.get_json()
        payout_ref = db.collection("payout_requests").document(payout_id)
        payout_doc = payout_ref.get()
        
        if not payout_doc.exists: return jsonify({"error": "Payout not found"}), 404
        payout_ref.update(data)
        
        if data.get("status") == "paid":
            pinfo = payout_doc.to_dict()
            amount = pinfo.get("amount", pinfo.get("netPayable", 0))
            db.collection("transactions").add({
                "txId": f"TXN-{int(datetime.now(timezone.utc).timestamp())}",
                "date": datetime.now(timezone.utc).strftime("%d %b %Y"),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "type": "Payout",
                "brand": pinfo.get("brand", "Unknown Seller"),
                "amount": f"- ₹{amount}",
                "status": f"Paid (UTR: {data.get('utr', 'N/A')})",
                "payout_id": payout_id
            })
        return jsonify({"status": "Payout updated and ledger recorded"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# 8. SELLER FINANCE & PAYOUT ROUTES
# ==========================================
@app.route("/api/v1/seller/dashboard", methods=["GET"])
@seller_required
def get_isolated_seller_data():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        current_seller_email = request.seller_email 
        
        config_doc = db.collection("settings").document("financial_settings").get()
        config = config_doc.to_dict() if config_doc.exists else {}
        
        commission_percent = float(config.get("platformCommission", 30.0))
        tcs_percent = float(config.get("tcsRate", 1.0))
        gst_threshold = float(config.get("gstThreshold", 2500.0))
        gst_lower_rate = float(config.get("gstLowerRate", 5.0))
        gst_upper_rate = float(config.get("gstUpperRate", 18.0))
        
        orders_query = db.collection("orders").where("sellerEmails", "array_contains", current_seller_email).get()
        
        secure_wallet = {"available": 0, "pending": 0, "lifetime": 0}
        isolated_sales_ledger = []
        
        for doc in orders_query:
            order = doc.to_dict()
            order_status = order.get("status", "pending")
            
            # FIXED: Added "processing" to the allowed list so COD orders are counted
            if order_status not in ["paid", "processing", "delivered", "settled_override"]: 
                continue
                
            # 1. Determine if this seller pays for the discount
            order_discount = float(order.get("discount_applied", 0))
            promo_role = order.get("promo_creator_role")
            promo_email = order.get("promo_seller_email")
            seller_bears_discount = (promo_role == "seller" and promo_email == current_seller_email)
            
            # 2. Get total gross for this seller to proportionately divide the discount
            seller_items = [i for i in order.get("items", []) if i.get("sellerEmail") == current_seller_email]
            seller_gross_total = sum(float(i.get("price", 0)) * int(i.get("quantity", 1)) for i in seller_items)
                
            for item in seller_items:
                item_price = float(item.get("price", 0))
                item_qty = int(item.get("quantity", 1))
                gross_item_revenue = item_price * item_qty
                
                # 3. Deduct proportional discount if the seller created the code
                item_discount = 0
                if seller_bears_discount and seller_gross_total > 0:
                    item_discount = order_discount * (gross_item_revenue / seller_gross_total)
                    
                discounted_item_revenue = gross_item_revenue - item_discount
                
                # 4. JAMBA commission is now taken from the discounted price!
                jamba_fee = discounted_item_revenue * (commission_percent / 100.0)
                commission_gst = jamba_fee * 0.18
                
                if discounted_item_revenue <= gst_threshold:
                    product_gst_percent = gst_lower_rate
                else:
                    product_gst_percent = gst_upper_rate
                    
                net_product_value = discounted_item_revenue / (1 + (product_gst_percent / 100.0))
                tcs_amount = net_product_value * (tcs_percent / 100.0)
                
                net_seller_earnings = discounted_item_revenue - jamba_fee - commission_gst - tcs_amount
                
                isolated_sales_ledger.append({
                    "order_id": order.get("jamba_order_id", "N/A"),
                    "date": order.get("created_at"),
                    "product_name": item.get("name", item.get("title", "Product")),
                    "qty": item_qty,
                    "gross": round(discounted_item_revenue, 2),
                    "fee": round(jamba_fee, 2),
                    "commission_gst": round(commission_gst, 2),
                    "tcs": round(tcs_amount, 2),
                    "net": round(net_seller_earnings, 2),
                    "status": order_status
                })
                
                if order_status in ["delivered", "settled_override"]:
                    secure_wallet["available"] += net_seller_earnings
                # FIXED: Added "processing" to pending funds logic
                elif order_status in ["paid", "processing"]:
                    secure_wallet["pending"] += net_seller_earnings
                
                secure_wallet["lifetime"] += net_seller_earnings

        payouts_query = db.collection("payout_requests").where("email", "==", current_seller_email).get()
        for doc in payouts_query:
            amt = float(doc.to_dict().get("amount", 0))
            if doc.to_dict().get("status") in ["paid", "pending"]:
                secure_wallet["available"] -= amt
            
        if secure_wallet["available"] < 0: secure_wallet["available"] = 0
        isolated_sales_ledger.sort(key=lambda x: x.get("date", ""), reverse=True)

        return jsonify({
            "wallet": {
                "available": round(secure_wallet["available"], 2),
                "pending": round(secure_wallet["pending"], 2),
                "lifetime": round(secure_wallet["lifetime"], 2)
            },
            "sales_ledger": isolated_sales_ledger
        }), 200
    except Exception as e:
        logger.error(f"Pipeline error: {e}")
        return jsonify({"error": "Failed to securely route financial data"}), 500

@app.route("/api/v1/seller/payouts/history", methods=["GET"])
@seller_required
def get_payout_history():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        payouts_query = db.collection("payout_requests").where("email", "==", request.seller_email).get()
        history = [{**doc.to_dict(), "id": doc.id} for doc in payouts_query]
        history.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return jsonify(history), 200
    except Exception as e: 
        logger.error(f"History error: {e}")
        return jsonify({"error": "Failed to load history"}), 500

@app.route("/api/v1/seller/payouts/request", methods=["POST"])
@seller_required
def request_payout():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        data = request.get_json()
        amount = float(data.get("amount", 0))
        if amount <= 0: return jsonify({"error": "Invalid payout amount"}), 400
            
        _, doc_ref = db.collection("payout_requests").add({
            "email": request.seller_email,
            "brand": data.get("brand", "Unknown Brand"),
            "amount": amount,      
            "netPayable": amount,   
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "utr": ""
        })
        return jsonify({"status": "success", "id": doc_ref.id}), 201
    except Exception as e: 
        logger.error(f"Request error: {e}")
        return jsonify({"error": "Failed to process request"}), 500

# ==========================================
# 9. PROMO CODE ENGINE (ADMIN & SELLER)
# ==========================================
@app.route("/admin/promocodes", methods=["GET", "POST"])
@admin_required
def admin_promocodes():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        if request.method == "GET":
            docs = db.collection("promocodes").order_by("created_at", direction=firestore.Query.DESCENDING).get()
            return jsonify([{**doc.to_dict(), "id": doc.id} for doc in docs]), 200
            
        if request.method == "POST":
            data = request.get_json()
            code = data.get("code", "").strip().upper()
            
            existing = db.collection("promocodes").where("code", "==", code).get()
            if len(existing) > 0:
                return jsonify({"error": f"Promo code {code} already exists!"}), 400
                
            promo_data = {
                "code": code,
                "type": data.get("type", "percentage"), 
                "value": float(data.get("value", 0)),
                "creator_role": "admin",
                "seller_email": None,
                "status": "active", 
                "usage_limit": data.get("usage_limit", "unlimited"), 
                "applicable_payment_method": data.get("payment_method", "all"), 
                "valid_from": data.get("valid_from"), 
                "valid_until": data.get("valid_until"),
                "used_by": [], 
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            _, doc_ref = db.collection("promocodes").add(promo_data)
            return jsonify({"status": "success", "id": doc_ref.id}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/promocodes/<doc_id>", methods=["PUT", "DELETE"])
@admin_required
def manage_promocode(doc_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        doc_ref = db.collection("promocodes").document(doc_id)
        if request.method == "PUT":
            update_data = request.get_json()
            doc_ref.update({"status": update_data.get("status", "pending")})
            return jsonify({"status": "success"}), 200
        if request.method == "DELETE":
            doc_ref.delete()
            return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/v1/seller/promocodes", methods=["GET", "POST"])
@seller_required
def seller_promocodes():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        if request.method == "GET":
            docs = db.collection("promocodes").where("seller_email", "==", request.seller_email).get()
            promos = [{**doc.to_dict(), "id": doc.id} for doc in docs]
            promos.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            return jsonify(promos), 200

        if request.method == "POST":
            data = request.get_json()
            code = data.get("code", "").strip().upper()

            existing = db.collection("promocodes").where("code", "==", code).get()
            if len(existing) > 0:
                return jsonify({"error": f"Promo code {code} is already taken!"}), 400

            promo_data = {
                "code": code,
                "type": data.get("type", "percentage"),
                "value": float(data.get("value", 0)),
                "creator_role": "seller",
                "seller_email": request.seller_email,
                "status": "pending", 
                "usage_limit": data.get("usage_limit", "unlimited"),
                "applicable_payment_method": data.get("payment_method", "all"), 
                "valid_from": data.get("valid_from"),
                "valid_until": data.get("valid_until"),
                "used_by": [],
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            _, doc_ref = db.collection("promocodes").add(promo_data)
            return jsonify({"status": "success", "id": doc_ref.id}), 201
    except Exception as e:
        logger.error(f"Seller Promo Error: {e}")
        return jsonify({"error": "Failed to process promo code"}), 500

# ==========================================
# 10. CUSTOMER CHECKOUT PROMO VALIDATION
# ==========================================
@app.route("/api/v1/promocodes/validate", methods=["POST"])
def validate_promocode():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        data = request.get_json()
        code = data.get("code", "").strip().upper()
        customer_email = data.get("email", "").strip()

        query = db.collection("promocodes").where("code", "==", code).limit(1).get()
        if not query:
            return jsonify({"error": "Invalid promo code"}), 404

        promo = query[0].to_dict()

        if promo.get("status") != "active":
            return jsonify({"error": "Promo code is not active or awaiting approval"}), 400

        # FIXED TIMEZONE CHECK
        now = datetime.now(timezone.utc).isoformat()
        
        if promo.get("valid_from"):
            promo_start = promo.get("valid_from")
            # If the date from Firebase doesn't specify a timezone, append IST (+05:30)
            if not promo_start.endswith("Z") and "+" not in promo_start:
                promo_start += "+05:30" 
            if now < promo_start:
                return jsonify({"error": "Promo code is not yet valid"}), 400
                
        if promo.get("valid_until"):
            promo_end = promo.get("valid_until")
            if not promo_end.endswith("Z") and "+" not in promo_end:
                promo_end += "+05:30"
            if now > promo_end:
                return jsonify({"error": "Promo code has expired"}), 400

        if promo.get("usage_limit") == "single":
            if customer_email and customer_email in promo.get("used_by", []):
                return jsonify({"error": "You have already used this promo code"}), 400

        return jsonify({
            "status": "success",
            "type": promo.get("type"),
            "value": promo.get("value"),
            "creator_role": promo.get("creator_role"),
            "seller_email": promo.get("seller_email")
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# 11. RUN THE SERVER
# ==========================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)