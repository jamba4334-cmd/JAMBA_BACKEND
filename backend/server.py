# ==========================================
# 1. IMPORTS
# ==========================================
import os
import json
import logging
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
import razorpay
import firebase_admin
from firebase_admin import credentials, firestore, auth as firebase_auth

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
FIREBASE_KEY_PATH = os.getenv("FIREBASE_KEY_PATH", "firebase-key.json")

try:
    if not firebase_admin._apps:
        cred = credentials.Certificate(FIREBASE_KEY_PATH)
        firebase_admin.initialize_app(cred)
    db = firestore.client()
    logger.info("✅ Firebase initialized successfully.")
except Exception as e:
    logger.error(f"❌ Firebase initialization failed: {e}")
    db = None

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "rzp_test_SvVCY9dpYnL1Kq")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "YOUR_SECRET_KEY_HERE")

try:
    razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    logger.info("✅ Razorpay client initialized.")
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
            if decoded_token.get("email") != ALLOWED_ADMIN_EMAIL:
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
            
            # Verify the seller exists in the authorized_sellers collection
            seller_doc = db.collection("authorized_sellers").document(email).get()
            if not seller_doc.exists:
                return jsonify({"error": "Forbidden: Seller account not found"}), 403
                
            # Attach the verified email to the request context
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
    return jsonify({"server": "running"}), 200

@app.route("/create-order", methods=["POST"])
def create_order():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        data = request.get_json()
        cart = data.get("cart", [])
        customer_email = data.get("customer", "guest@jambawear.com")
        shipping_address = data.get("shippingAddress", {})
        payment_method = data.get("payment_method", "Razorpay")

        secure_subtotal = 0
        enriched_cart = []
        seller_emails_set = set()

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
            secure_subtotal += real_price * quantity
            
            seller_email = product.get("sellerEmail", "")
            if seller_email: seller_emails_set.add(seller_email)
            
            is_returnable = product.get("isReturnable", True)

            item.update({
                "price": real_price,
                "brandName": product.get("brandName", ""),
                "sellerName": product.get("sellerName", ""),
                "sellerEmail": seller_email,
                "isReturnable": is_returnable
            })
            enriched_cart.append(item)

        shipping_fee = 149 if secure_subtotal < 1999 else 0
        final_total = secure_subtotal + shipping_fee
        unique_jamba_id = "JB" + datetime.now().strftime("%y%m%d%H%M%S")

        order_data = {
            "jamba_order_id": unique_jamba_id,
            "email": customer_email,
            "items": enriched_cart,
            "subtotal": secure_subtotal,
            "shipping_fee": shipping_fee,
            "total": final_total,
            "status": "pending",
            "payment_method": payment_method,
            "shippingAddress": shipping_address,
            "created_at": datetime.utcnow().isoformat(),
            "sellerEmails": list(seller_emails_set)
        }

        if payment_method == "COD":
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
# 6. ADMIN ROUTES (Protected)
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
        except Exception: return jsonify({"error": "Internal server error"}), 500
    if request.method == "POST":
        try:
            data = request.get_json()
            data["created_at"] = datetime.utcnow().isoformat()
            _, doc_ref = db.collection("products").add(data)
            return jsonify({"status": "success", "id": doc_ref.id}), 201
        except Exception: return jsonify({"error": "Failed to create product"}), 500

@app.route("/admin/products/<doc_id>", methods=["PUT", "DELETE"])
@admin_required
def admin_product_detail(doc_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    doc_ref = db.collection("products").document(doc_id)
    if request.method == "PUT":
        doc_ref.update(request.get_json())
        return jsonify({"status": "success"}), 200
    if request.method == "DELETE":
        doc_ref.delete()
        return jsonify({"status": "success"}), 200

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
    except Exception: return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/orders/<order_id>", methods=["PUT"])
@admin_required
def update_order(order_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    db.collection("orders").document(order_id).update(request.get_json())
    return jsonify({"status": "success"}), 200

@app.route("/admin/orders/<order_id>/force-clear", methods=["POST"])
@admin_required
def force_clear_order(order_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    db.collection("orders").document(order_id).update({"status": "settled_override"})
    return jsonify({"status": "success", "message": "Escrow released manually."}), 200

@app.route("/admin/customers", methods=["GET"])
@admin_required
def admin_customers():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    limit = int(request.args.get("limit", 50))
    customers = [{**doc.to_dict(), "id": doc.id} for doc in db.collection("users").limit(limit).get()]
    return jsonify(customers), 200

@app.route("/admin/settings/<doc_id>", methods=["GET", "PUT"])
@admin_required
def admin_settings(doc_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    if request.method == "GET":
        doc = db.collection("settings").document(doc_id).get()
        if doc.exists: return jsonify(doc.to_dict()), 200
        return jsonify({"tribes": []} if doc_id == "tribe_categories" else {}), 200
    if request.method == "PUT":
        data = request.get_json()
        if doc_id == "tribe_categories": data["last_updated"] = datetime.utcnow().isoformat()
        db.collection("settings").document(doc_id).set(data, merge=True)
        return jsonify({"status": "Settings updated"}), 200

@app.route("/admin/sellers", methods=["GET", "POST"])
@admin_required
def admin_sellers():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    if request.method == "GET":
        sellers = [{**doc.to_dict(), "id": doc.id} for doc in db.collection("authorized_sellers").get()]
        return jsonify(sellers), 200
    if request.method == "POST":
        email = request.get_json().get("email")
        db.collection("authorized_sellers").document(email).set({
            "email": email, "addedAt": datetime.utcnow().isoformat(), "addedBy": ALLOWED_ADMIN_EMAIL
        })
        return jsonify({"status": "Seller authorized"}), 201

@app.route("/admin/sellers/<email>", methods=["DELETE"])
@admin_required
def remove_seller(email):
    db.collection("authorized_sellers").document(email).delete()
    return jsonify({"status": "Seller removed"}), 200

# ==========================================
# 7. ADMIN FINANCE, LEDGERS & GOD-MODE
# ==========================================
@app.route("/admin/payouts", methods=["GET"])
@admin_required
def admin_payouts():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    status_filter = request.args.get("status")
    query = db.collection("payout_requests")
    if status_filter: query = query.where("status", "==", status_filter)
    payouts = [{**doc.to_dict(), "id": doc.id} for doc in query.get()]
    return jsonify(payouts), 200

@app.route("/admin/finance/customer-payments", methods=["GET"])
@admin_required
def admin_customer_payments():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
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

@app.route("/admin/finance/kpis", methods=["GET"])
@admin_required
def admin_finance_kpis():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
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

@app.route("/admin/transactions", methods=["GET"])
@admin_required
def admin_transactions():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    limit = int(request.args.get("limit", 100))
    docs = db.collection("transactions").order_by("created_at", direction=firestore.Query.DESCENDING).limit(limit).get()
    return jsonify([{**doc.to_dict(), "id": doc.id} for doc in docs]), 200

@app.route("/admin/finance/adjust", methods=["POST"])
@admin_required
def inject_financial_adjustment():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    data = request.get_json()
    brand = data.get("brand", "Global Correction")
    amount = float(data.get("amount", 0))
    db.collection("transactions").add({
        "txId": f"ADJ-{int(datetime.utcnow().timestamp())}",
        "date": datetime.utcnow().strftime("%d %b %Y"),
        "created_at": datetime.utcnow().isoformat(),
        "type": "Bonus" if amount >= 0 else "Penalty",
        "brand": brand,
        "amount": f"+ ₹{amount}" if amount >= 0 else f"- ₹{abs(amount)}",
        "status": f"Applied: {data.get('reason', 'Force Adj')}"
    })
    return jsonify({"status": "success"}), 201

@app.route("/admin/payouts/<payout_id>", methods=["PUT"])
@admin_required
def update_payout(payout_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    data = request.get_json()
    payout_ref = db.collection("payout_requests").document(payout_id)
    payout_doc = payout_ref.get()
    
    if not payout_doc.exists: return jsonify({"error": "Payout not found"}), 404
    payout_ref.update(data)
    
    if data.get("status") == "paid":
        pinfo = payout_doc.to_dict()
        amount = pinfo.get("amount", pinfo.get("netPayable", 0))
        db.collection("transactions").add({
            "txId": f"TXN-{int(datetime.utcnow().timestamp())}",
            "date": datetime.utcnow().strftime("%d %b %Y"),
            "created_at": datetime.utcnow().isoformat(),
            "type": "Payout",
            "brand": pinfo.get("brand", "Unknown Seller"),
            "amount": f"- ₹{amount}",
            "status": f"Paid (UTR: {data.get('utr', 'N/A')})",
            "payout_id": payout_id
        })
    return jsonify({"status": "Payout updated and ledger recorded"}), 200

# ==========================================
# 8. SELLER FINANCE & PAYOUT ROUTES (SECURE PIPELINE)
# ==========================================
@app.route("/api/v1/seller/dashboard", methods=["GET"])
@seller_required
def get_isolated_seller_data():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        current_seller_email = request.seller_email 
        
        # Macro Query
        orders_query = db.collection("orders").where("sellerEmails", "array_contains", current_seller_email).get()
        
        secure_wallet = {"available": 0, "pending": 0, "lifetime": 0}
        isolated_sales_ledger = []
        
        for doc in orders_query:
            order = doc.to_dict()
            order_status = order.get("status", "pending")
            
            if order_status not in ["paid", "delivered", "settled_override"]: 
                continue
                
            # Micro Filter
            for item in order.get("items", []):
                if item.get("sellerEmail") == current_seller_email:
                    gross_item_revenue = float(item.get("price", 0)) * int(item.get("quantity", 1))
                    jamba_fee = gross_item_revenue * 0.30
                    net_seller_earnings = gross_item_revenue - jamba_fee
                    
                    isolated_sales_ledger.append({
                        "order_id": order.get("jamba_order_id", "N/A"),
                        "date": order.get("created_at"),
                        "product_name": item.get("name", item.get("title", "Product")),
                        "qty": int(item.get("quantity", 1)),
                        "gross": round(gross_item_revenue, 2),
                        "fee": round(jamba_fee, 2),
                        "net": round(net_seller_earnings, 2),
                        "status": order_status
                    })
                    
                    if order_status in ["delivered", "settled_override"]:
                        secure_wallet["available"] += net_seller_earnings
                    elif order_status == "paid":
                        secure_wallet["pending"] += net_seller_earnings
                    
                    secure_wallet["lifetime"] += net_seller_earnings

        # Subtract withdrawn payouts
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
            
        gross_amount = round(amount / 0.7, 2)
        _, doc_ref = db.collection("payout_requests").add({
            "email": request.seller_email,
            "brand": data.get("brand", "Unknown Brand"),
            "amount": amount,      
            "netPayable": amount,   
            "grossAmount": gross_amount,
            "jambaFee": round(gross_amount - amount, 2),
            "deductions": 0,
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
            "utr": ""
        })
        return jsonify({"status": "success", "id": doc_ref.id}), 201
    except Exception as e: 
        logger.error(f"Request error: {e}")
        return jsonify({"error": "Failed to process request"}), 500

# ==========================================
# 9. RUN THE SERVER
# ==========================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)