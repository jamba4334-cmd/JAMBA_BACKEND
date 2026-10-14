# ==========================================
# 1. IMPORTS
# ==========================================
import os
import json
import logging
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from dotenv import load_dotenv

import razorpay
import firebase_admin
from firebase_admin import credentials, firestore, auth as firebase_auth

from fpdf import FPDF
import io
import re
import uuid

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

# SECURITY: never fall back to "*". Set ALLOWED_ORIGINS=https://jambawear.in,https://www.jambawear.in
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",") if o.strip()]
CORS(app, resources={r"/*": {"origins": ALLOWED_ORIGINS}},
     allow_headers=["Authorization", "Content-Type"], methods=["GET", "POST", "PUT", "DELETE"], max_age=600)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB request cap

# SECURITY: super-admin email comes only from the environment (set ADMIN_EMAIL in .env).
ALLOWED_ADMIN_EMAIL = (os.getenv("ADMIN_EMAIL") or "").strip().lower()

# ==========================================
# INPUT VALIDATION HELPERS
# ==========================================
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,}$")
DOC_ID_RE = re.compile(r"^[A-Za-z0-9_\-@.]{1,128}$")
PROMO_RE = re.compile(r"^[A-Z0-9_-]{3,24}$")

class BadInput(ValueError):
    pass

def v_email(value, field="email"):
    v = str(value or "").strip().lower()
    if not EMAIL_RE.match(v): raise BadInput(f"Invalid {field}")
    return v

def v_doc_id(value, field="id"):
    v = str(value or "").strip()
    if not DOC_ID_RE.match(v) or "/" in v: raise BadInput(f"Invalid {field}")
    return v

def v_int(value, lo, hi, field="number"):
    try: n = int(value)
    except (TypeError, ValueError): raise BadInput(f"Invalid {field}")
    if n < lo or n > hi: raise BadInput(f"{field} out of range")
    return n

def v_float(value, lo, hi, field="amount"):
    try: n = float(value)
    except (TypeError, ValueError): raise BadInput(f"Invalid {field}")
    if n != n or n < lo or n > hi: raise BadInput(f"{field} out of range")
    return round(n, 2)

def v_choice(value, choices, field="value"):
    v = str(value or "").strip().lower()
    if v not in choices: raise BadInput(f"Invalid {field}")
    return v

def v_str(value, max_len=200, field="text"):
    v = str(value or "").strip()
    if len(v) > max_len: raise BadInput(f"{field} too long")
    return v

def pick(data, allowed):
    """Allow-list fields to stop mass-assignment of arbitrary keys."""
    return {k: data[k] for k in allowed if k in data}

PRODUCT_FIELDS = ["name", "description", "selling_price", "mrp", "category", "tribe", "images",
                  "sizes", "colors", "stock", "isReturnable", "brandName", "sellerName",
                  "sellerEmail", "item_id", "status", "tags", "hsn", "weight"]
ORDER_ADMIN_FIELDS = ["status", "tracking_id", "courier", "admin_note", "delivered_at", "return_status"]
PAYOUT_ADMIN_FIELDS = ["status", "utr", "admin_note"]

@app.errorhandler(BadInput)
def handle_bad_input(e):
    return jsonify({"error": str(e)}), 400

@app.errorhandler(413)
def handle_too_large(_e):
    return jsonify({"error": "Request too large"}), 413

@app.errorhandler(404)
def handle_404(_e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(Exception)
def handle_unexpected(e):
    # SECURITY: log full details server-side only, never return them.
    logger.error("Unhandled error", exc_info=True)
    return jsonify({"error": "Internal server error"}), 500

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
# 4. SECURITY MIDDLEWARE & HEADERS
# ==========================================
@app.after_request
def apply_security_headers(response):
    """Globally injects security headers to prevent XSS, Clickjacking, and MIME sniffing."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Note: If your frontend and backend are on different domains, 'self' restricts fetching. 
    # Modify default-src or connect-src if you host API and frontend separately.
    # API returns JSON/PDF only, so lock CSP down completely.
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Resource-Policy"] = "same-site"
    if request.path.startswith(("/admin", "/api/v1/seller")) or request.headers.get("Authorization"):
        response.headers["Cache-Control"] = "no-store"
    response.headers.pop("Server", None)
    return response

def _verify_bearer():
    """Returns decoded Firebase token or None. Rejects revoked tokens and unverified emails."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[7:].strip()
    if not token or len(token) > 4096:
        return None
    try:
        decoded = firebase_auth.verify_id_token(token, check_revoked=True)
    except Exception:
        return None
    # SECURITY: an attacker can register email/password with someone else's address.
    # Only trust emails Firebase has verified (Google sign-in is always verified).
    if not decoded.get("email") or decoded.get("email_verified") is not True:
        return None
    return decoded

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        decoded = _verify_bearer()
        if not decoded:
            return jsonify({"error": "Unauthorized"}), 401
        email = decoded["email"].lower()
        if db is None:
            return jsonify({"error": "Service unavailable"}), 503
        if ALLOWED_ADMIN_EMAIL and email == ALLOWED_ADMIN_EMAIL:
            request.admin_email = email
            return f(*args, **kwargs)
        admin_doc = db.collection("admin_users").document(email).get()
        if admin_doc.exists and admin_doc.to_dict().get("isAuthorized") is True:
            request.admin_email = email
            return f(*args, **kwargs)
        return jsonify({"error": "Forbidden"}), 403
    return decorated_function

def seller_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        decoded = _verify_bearer()
        if not decoded:
            return jsonify({"error": "Unauthorized"}), 401
        if db is None:
            return jsonify({"error": "Service unavailable"}), 503
        email = decoded["email"].lower()
        if not db.collection("authorized_sellers").document(email).get().exists:
            return jsonify({"error": "Forbidden"}), 403
        request.seller_email = email
        return f(*args, **kwargs)
    return decorated_function

def optional_user():
    """Decoded token for customers (may be None for guest checkout)."""
    return _verify_bearer()

# ==========================================
# 5. PUBLIC ROUTES (Customer Facing)
# ==========================================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"server": "running", "status": "ok"}), 200

@app.route("/create-order", methods=["POST"])
def create_order():
    if db is None: 
        return jsonify({"error": "Service temporarily unavailable."}), 503
        
    try:
        data = request.get_json()
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Invalid JSON payload."}), 400

        # Strict Input Validation
        cart = data.get("cart")
        if not isinstance(cart, list) or len(cart) == 0:
            return jsonify({"error": "Cart cannot be empty."}), 400

        if len(cart) > 50:
            return jsonify({"error": "Too many items in cart."}), 400
        # SECURITY: identity comes from the verified token, not the request body,
        # so a user cannot spend someone else's single-use promo.
        user = optional_user()
        customer_email = user["email"].lower() if user else v_email(data.get("customer"), "customer email")
        customer_uid = user["uid"] if user else None
        raw_addr = data.get("shippingAddress", {})
        if not isinstance(raw_addr, dict):
            raw_addr = {}
        shipping_address = {k: v_str(raw_addr.get(k, ""), 200, k) for k in
                            ["name", "phone", "line1", "line2", "city", "state", "pincode", "landmark"]}
            
        payment_method = "COD" if str(data.get("payment_method", "Razorpay")).strip().upper() == "COD" else "Razorpay"
        promo_code_str = str(data.get("promo_code", "")).strip().upper()

        secure_subtotal = 0
        enriched_cart = []
        seller_emails_set = set()

        # 1. VERIFY PROMO CODE
        promo_data = None
        if promo_code_str:
            promo_query = db.collection("promocodes").where("code", "==", promo_code_str).where("status", "==", "active").limit(1).get()
            if promo_query:
                temp_promo = promo_query[0].to_dict()
                
                now = datetime.now(timezone.utc).isoformat()
                
                is_valid_time = True
                if temp_promo.get("valid_from"):
                    promo_start = temp_promo.get("valid_from")
                    if not promo_start.endswith("Z") and "+" not in promo_start:
                        promo_start += "+05:30"
                    if now < promo_start: is_valid_time = False
                        
                if temp_promo.get("valid_until"):
                    promo_end = temp_promo.get("valid_until")
                    if not promo_end.endswith("Z") and "+" not in promo_end:
                        promo_end += "+05:30" 
                    if now > promo_end: is_valid_time = False
                
                is_valid_usage = True
                if temp_promo.get("usage_limit") == "single" and customer_email in temp_promo.get("used_by", []): is_valid_usage = False
                
                promo_payment_method = temp_promo.get("applicable_payment_method", "all")
                if promo_payment_method == "online" and payment_method.upper() == "COD":
                    return jsonify({"error": "This promo code is strictly for Prepaid Online Orders."}), 400
                if promo_payment_method == "cod" and payment_method.upper() != "COD":
                    return jsonify({"error": "This promo code is only valid for Cash on Delivery orders."}), 400

                if is_valid_time and is_valid_usage:
                    promo_data = temp_promo
                    promo_doc_id = promo_query[0].id

        # 2. PROCESS CART
        total_discount = 0
        seller_eligible_subtotal = 0

        for item in cart:
            if not isinstance(item, dict):
                return jsonify({"error": "Invalid cart item."}), 400
            item_id = v_doc_id(item.get("id"), "product id")
            # SECURITY: negative/huge quantities previously produced negative totals.
            quantity = v_int(item.get("quantity", 1), 1, 20, "quantity")
            
            doc_ref = db.collection("products").document(item_id).get()
            if not doc_ref.exists:
                query = db.collection("products").where("item_id", "==", item_id).limit(1).get()
                if not query: return jsonify({"error": f"Product out of stock."}), 400
                product = query[0].to_dict()
            else:
                product = doc_ref.to_dict()

            real_price = float(product.get("selling_price", 0))
            item_total = real_price * quantity
            secure_subtotal += item_total
            
            seller_email = product.get("sellerEmail", "")
            if seller_email: seller_emails_set.add(seller_email)
            
            is_returnable = product.get("isReturnable", True)

            if promo_data and promo_data.get("creator_role") == "seller":
                if promo_data.get("seller_email") == seller_email:
                    seller_eligible_subtotal += item_total

            item = {
                "id": item_id,
                "quantity": quantity,
                "size": v_str(item.get("size", ""), 20, "size"),
                "color": v_str(item.get("color", ""), 40, "color"),
                "name": product.get("name", ""),
                "price": real_price,
                "brandName": product.get("brandName", ""),
                "sellerName": product.get("sellerName", ""),
                "sellerEmail": seller_email,
                "isReturnable": is_returnable
            }
            enriched_cart.append(item)

        # 3. CALCULATE MATH
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

        taxable_value = secure_subtotal - total_discount
        
        if taxable_value <= 2500:
            total_gst = taxable_value * 0.05
        else:
            total_gst = taxable_value * 0.18

        shipping_fee = 149 if secure_subtotal < 1999 else 0
        final_total = max(taxable_value + shipping_fee, 0)
        if final_total <= 0 or final_total > 1_000_000:
            return jsonify({"error": "Invalid order total."}), 400
        unique_jamba_id = "JB" + datetime.now(timezone.utc).strftime("%y%m%d") + uuid.uuid4().hex[:6].upper()

        order_data = {
            "jamba_order_id": unique_jamba_id,
            "email": customer_email,
            "userId": customer_uid,
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

    except ValueError as ve:
        logger.warning(f"Validation Error in create_order: {ve}")
        return jsonify({"error": "Invalid data format provided."}), 400
    except Exception as e:
        logger.error(f"Critical error in create_order: {str(e)}", exc_info=True)
        return jsonify({"error": "An internal server error occurred while processing your order."}), 500

@app.route("/verify-payment", methods=["POST"])
def verify_payment():
    if db is None: return jsonify({"error": "Database service unavailable."}), 503
    if not razorpay_client: return jsonify({"error": "Payment gateway unavailable."}), 503
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid payload."}), 400
            
        razorpay_order_id = v_str(data.get("razorpay_order_id"), 64, "order id")
        rose_payment_id = v_str(data.get("razorpay_payment_id"), 64, "payment id")
        razorpay_signature = v_str(data.get("razorpay_signature"), 128, "signature")
        if not (razorpay_order_id and rose_payment_id and razorpay_signature):
            return jsonify({"error": "Invalid payload."}), 400

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
        
    except razorpay.errors.SignatureVerificationError:
        logger.warning(f"Signature verification failed for order {razorpay_order_id}")
        return jsonify({"error": "Invalid payment signature."}), 400
    except Exception as e:
        logger.error(f"Error in verify_payment: {str(e)}", exc_info=True)
        return jsonify({"error": "An internal server error occurred."}), 500

@app.route("/api/orders/<order_id>/invoice", methods=["GET"])
def generate_invoice(order_id):
    if db is None: 
        return jsonify({"error": "Service unavailable"}), 503
        
    try:
        order_id = v_doc_id(order_id, "order id")
        # SECURITY: invoices contain name, address and phone - require the owner (or an admin).
        user = optional_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        order_doc = db.collection("orders").document(order_id).get()
        if not order_doc.exists:
            return jsonify({"error": "Order not found"}), 404
        order_data = order_doc.to_dict()
        req_email = user["email"].lower()
        is_owner = order_data.get("userId") == user["uid"] or (order_data.get("email") or "").lower() == req_email
        is_seller = req_email in [e.lower() for e in order_data.get("sellerEmails", [])]
        is_admin = (ALLOWED_ADMIN_EMAIL and req_email == ALLOWED_ADMIN_EMAIL) or (
            (lambda d: d.exists and d.to_dict().get("isAuthorized") is True)(db.collection("admin_users").document(req_email).get()))
        if not (is_owner or is_seller or is_admin):
            return jsonify({"error": "Order not found"}), 404

        seller_email = order_data.get("sellerEmails", [""])[0]
        seller_app_doc = db.collection("authorized_sellers").document(seller_email).get()
        seller_data = seller_app_doc.to_dict() if seller_app_doc.exists else {}
        kyc_data = seller_data.get("kycData", {})

        has_gst = kyc_data.get("hasGst", False)
        document_title = "TAX INVOICE" if has_gst else "BILL OF SUPPLY"
        gstin_display = kyc_data.get("gstNumber", "UNREGISTERED")

        pdf = FPDF()
        pdf.add_page()
        
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt=document_title, ln=True, align='C')
        
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 6, txt=f"Order ID: {order_data.get('jamba_order_id', order_id)}", ln=True, align='C')
        pdf.cell(200, 6, txt=f"Date: {order_data.get('created_at', '')[:10]}", ln=True, align='C')
        pdf.ln(10)

        pdf.set_font("Arial", 'B', 10)
        pdf.cell(100, 6, txt="Sold By:", ln=False)
        pdf.cell(100, 6, txt="Billed To:", ln=True)
        
        pdf.set_font("Arial", size=10)
        pdf.cell(100, 6, txt=seller_data.get("brandName", "Jambawear Artisan"), ln=False)
        pdf.cell(100, 6, txt=order_data.get("email", "Customer"), ln=True)
        pdf.cell(100, 6, txt=f"GSTIN / Status: {gstin_display}", ln=False)
        
        shipping = order_data.get("shippingAddress", {})
        pdf.cell(100, 6, txt=f"{shipping.get('city', '')}, {shipping.get('state', '')} {shipping.get('pincode', '')}", ln=True)
        pdf.ln(10)

        if not has_gst:
            pdf.set_font("Arial", 'I', 9)
            pdf.cell(200, 6, txt="* Statutory Declaration: Issuer is an unregistered artisan. No GST is collected on this supply.", ln=True)
            pdf.ln(5)

        pdf.set_font("Arial", 'B', 10)
        pdf.cell(80, 8, txt="Item Description", border=1)
        pdf.cell(30, 8, txt="Qty", border=1, align='C')
        pdf.cell(40, 8, txt="Price", border=1, align='C')
        pdf.cell(40, 8, txt="Total", border=1, align='C')
        pdf.ln(8)

        pdf.set_font("Arial", size=10)
        for item in order_data.get("items", []):
            name = str(item.get("name", item.get("title", "Product")))[:35]
            qty = str(item.get("quantity", 1))
            price = f"Rs. {float(item.get('price', 0)):.2f}"
            total = f"Rs. {float(item.get('price', 0)) * int(item.get('quantity', 1)):.2f}"
            
            pdf.cell(80, 8, txt=name, border=1)
            pdf.cell(30, 8, txt=qty, border=1, align='C')
            pdf.cell(40, 8, txt=price, border=1, align='C')
            pdf.cell(40, 8, txt=total, border=1, align='C')
            pdf.ln(8)

        pdf.ln(5)
        pdf.set_font("Arial", 'B', 10)
        pdf.cell(150, 8, txt="Subtotal:", align='R')
        pdf.cell(40, 8, txt=f"Rs. {order_data.get('subtotal', 0):.2f}", align='C', ln=True)
        
        if has_gst:
            pdf.cell(150, 8, txt="GST Applied:", align='R')
            pdf.cell(40, 8, txt=f"Rs. {order_data.get('total_gst', 0):.2f}", align='C', ln=True)
            
        pdf.cell(150, 8, txt="Shipping:", align='R')
        pdf.cell(40, 8, txt=f"Rs. {order_data.get('shipping_fee', 0):.2f}", align='C', ln=True)
        
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(150, 10, txt="Grand Total:", align='R')
        pdf.cell(40, 10, txt=f"Rs. {order_data.get('total', 0):.2f}", align='C', ln=True)

        pdf_bytes = pdf.output(dest='S').encode('latin1')
        return send_file(
            io.BytesIO(pdf_bytes), 
            mimetype='application/pdf', 
            as_attachment=True, 
            download_name=f"Invoice_{order_id}.pdf"
        )
        
    except Exception as e:
        logger.error(f"Invoice generation failed for order {order_id}: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to generate document"}), 500

# ==========================================
# 6. ADMIN ROUTES
# ==========================================
@app.route("/admin/products", methods=["GET", "POST"])
@admin_required
def admin_products():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    if request.method == "GET":
        try:
            limit = v_int(request.args.get("limit", 50), 1, 200, "limit")
            products = []
            docs = db.collection("products").order_by("created_at", direction=firestore.Query.DESCENDING).limit(limit).get()
            for doc in docs: products.append({**doc.to_dict(), "docId": doc.id})
            return jsonify(products), 200
        except Exception as e:
            logger.error(f"Error fetching admin products: {str(e)}", exc_info=True)
            return jsonify({"error": "Internal server error"}), 500
    if request.method == "POST":
        try:
            data = request.get_json()
            if not isinstance(data, dict): return jsonify({"error": "Invalid payload"}), 400
            data = pick(data, PRODUCT_FIELDS)
            if "selling_price" in data: data["selling_price"] = v_float(data["selling_price"], 1, 1_000_000, "price")
            data["created_at"] = datetime.now(timezone.utc).isoformat()
            data["created_by"] = request.admin_email
            _, doc_ref = db.collection("products").add(data)
            return jsonify({"status": "success", "id": doc_ref.id}), 201
        except Exception as e:
            logger.error(f"Error creating admin product: {str(e)}", exc_info=True)
            return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/products/<doc_id>", methods=["PUT", "DELETE"])
@admin_required
def admin_product_detail(doc_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        doc_ref = db.collection("products").document(v_doc_id(doc_id))
        if request.method == "PUT":
            data = request.get_json()
            if not isinstance(data, dict): return jsonify({"error": "Invalid payload"}), 400
            data = pick(data, PRODUCT_FIELDS)
            if "selling_price" in data: data["selling_price"] = v_float(data["selling_price"], 1, 1_000_000, "price")
            if not data: return jsonify({"error": "No valid fields"}), 400
            doc_ref.update(data)
            return jsonify({"status": "success"}), 200
        if request.method == "DELETE":
            doc_ref.delete()
            return jsonify({"status": "success"}), 200
    except Exception as e:
        logger.error(f"Error updating admin product {doc_id}: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

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
        logger.error(f"Error fetching admin orders: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/orders/<order_id>", methods=["PUT"])
@admin_required
def update_order(order_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        data = request.get_json()
        if not isinstance(data, dict): return jsonify({"error": "Invalid payload"}), 400
        data = pick(data, ORDER_ADMIN_FIELDS)
        if not data: return jsonify({"error": "No valid fields"}), 400
        data["updated_by"] = request.admin_email
        db.collection("orders").document(v_doc_id(order_id)).update(data)
        return jsonify({"status": "success"}), 200
    except Exception as e:
        logger.error(f"Error updating admin order {order_id}: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/orders/<order_id>/force-clear", methods=["POST"])
@admin_required
def force_clear_order(order_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        db.collection("orders").document(order_id).update({"status": "settled_override"})
        return jsonify({"status": "success", "message": "Escrow released manually."}), 200
    except Exception as e:
        logger.error(f"Error clearing admin order {order_id}: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/customers", methods=["GET"])
@admin_required
def admin_customers():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        limit = int(request.args.get("limit", 50))
        customers = [{**doc.to_dict(), "id": doc.id} for doc in db.collection("users").limit(limit).get()]
        return jsonify(customers), 200
    except Exception as e:
        logger.error(f"Error fetching admin customers: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/settings/<doc_id>", methods=["GET", "PUT"])
@admin_required
def admin_settings(doc_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    doc_id = v_doc_id(doc_id, "settings id")
    try:
        if request.method == "GET":
            doc = db.collection("settings").document(doc_id).get()
            if doc.exists: return jsonify(doc.to_dict()), 200
            return jsonify({"tribes": []} if doc_id == "tribe_categories" else {}), 200
        if request.method == "PUT":
            data = request.get_json()
            if not isinstance(data, dict): return jsonify({"error": "Invalid payload"}), 400
            if doc_id == "tribe_categories": data["last_updated"] = datetime.now(timezone.utc).isoformat()
            db.collection("settings").document(doc_id).set(data, merge=True)
            return jsonify({"status": "Settings updated"}), 200
    except Exception as e:
        logger.error(f"Error in admin settings {doc_id}: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

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
            data = request.get_json()
            if not isinstance(data, dict): return jsonify({"error": "Invalid payload"}), 400
            email = v_email(data.get("email"))
            db.collection("authorized_sellers").document(email).set({
                "email": email, "addedAt": datetime.now(timezone.utc).isoformat(), "addedBy": request.admin_email
            }, merge=True)
            return jsonify({"status": "Seller authorized"}), 201
    except Exception as e:
        logger.error(f"Error in admin sellers: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/sellers/<email>", methods=["DELETE"])
@admin_required
def remove_seller(email):
    try:
        email = v_email(email)
        db.collection("authorized_sellers").document(email).delete()
        return jsonify({"status": "Seller removed"}), 200
    except Exception as e:
        logger.error(f"Error removing seller {email}: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/seller_profiles/<email>", methods=["GET", "PUT"])
@admin_required
def admin_seller_profile(email):
    if db is None:
        return jsonify({"error": "Database unavailable"}), 503

    target_email = v_email(email)
    profile_ref = db.collection("seller_profiles").document(target_email)

    try:
        if request.method == "GET":
            profile = profile_ref.get()
            return jsonify(profile.to_dict() if profile.exists else {}), 200

        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get("storefront"), dict):
            return jsonify({"error": "Invalid request: storefront data is required"}), 400

        data = {"storefront": data["storefront"], "updated_at": datetime.now(timezone.utc).isoformat()}
        profile_ref.set(data, merge=True)
        return jsonify({"status": "Profile updated"}), 200
    except Exception as e:
        logger.error(f"Could not read or save seller storefront for {email}: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

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
        logger.error(f"Error in admin payouts: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

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
        logger.error(f"Error in customer payments: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

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
        logger.error(f"Error fetching finance KPIs: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/transactions", methods=["GET"])
@admin_required
def admin_transactions():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        limit = int(request.args.get("limit", 100))
        docs = db.collection("transactions").order_by("created_at", direction=firestore.Query.DESCENDING).limit(limit).get()
        return jsonify([{**doc.to_dict(), "id": doc.id} for doc in docs]), 200
    except Exception as e:
        logger.error(f"Error fetching transactions: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/finance/adjust", methods=["POST"])
@admin_required
def inject_financial_adjustment():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        data = request.get_json()
        if not isinstance(data, dict): return jsonify({"error": "Invalid payload"}), 400
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
        logger.error(f"Error injecting adjustment: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/payouts/<payout_id>", methods=["PUT"])
@admin_required
def update_payout(payout_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        data = request.get_json()
        if not isinstance(data, dict): return jsonify({"error": "Invalid payload"}), 400
        payout_ref = db.collection("payout_requests").document(v_doc_id(payout_id))
        payout_doc = payout_ref.get()
        
        if not payout_doc.exists: return jsonify({"error": "Payout not found"}), 404
        data = pick(data, PAYOUT_ADMIN_FIELDS)
        if "status" in data: data["status"] = v_choice(data["status"], {"pending", "approved", "on_hold", "paid", "rejected"}, "status")
        if "utr" in data: data["utr"] = v_str(data["utr"], 40, "UTR")
        if not data: return jsonify({"error": "No valid fields"}), 400
        data["updated_by"] = request.admin_email
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
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
        logger.error(f"Error updating payout {payout_id}: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

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
            
            if order_status not in ["paid", "processing", "delivered", "settled_override"]: 
                continue
                
            order_discount = float(order.get("discount_applied", 0))
            promo_role = order.get("promo_creator_role")
            promo_email = order.get("promo_seller_email")
            seller_bears_discount = (promo_role == "seller" and promo_email == current_seller_email)
            
            seller_items = [i for i in order.get("items", []) if i.get("sellerEmail") == current_seller_email]
            seller_gross_total = sum(float(i.get("price", 0)) * int(i.get("quantity", 1)) for i in seller_items)
                
            for item in seller_items:
                item_price = float(item.get("price", 0))
                item_qty = int(item.get("quantity", 1))
                gross_item_revenue = item_price * item_qty
                
                item_discount = 0
                if seller_bears_discount and seller_gross_total > 0:
                    item_discount = order_discount * (gross_item_revenue / seller_gross_total)
                    
                discounted_item_revenue = gross_item_revenue - item_discount
                
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
        logger.error(f"Pipeline error for seller {request.seller_email}: {str(e)}", exc_info=True)
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
        logger.error(f"History error for seller {request.seller_email}: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

def compute_available_balance(seller_email):
    """Server-side source of truth for what a seller can withdraw."""
    cfg_doc = db.collection("platform_config").document("tax").get()
    cfg = cfg_doc.to_dict() if cfg_doc.exists else {}
    commission = float(cfg.get("commissionPct", 10)) / 100
    gst_on_comm = float(cfg.get("gstOnCommissionPct", 18)) / 100
    tcs = float(cfg.get("tcsPct", 1)) / 100
    tds = float(cfg.get("tdsPct", 0.1)) / 100
    hold_days = int(cfg.get("holdDays", 7))
    cutoff = datetime.now(timezone.utc).timestamp() - hold_days * 86400
    earned = 0.0
    for o in db.collection("orders").where("sellerEmails", "array_contains", seller_email).get():
        od = o.to_dict()
        if od.get("status") != "delivered":
            continue
        delivered_at = od.get("delivered_at") or od.get("created_at") or ""
        try:
            if datetime.fromisoformat(str(delivered_at).replace("Z", "+00:00")).timestamp() > cutoff:
                continue
        except ValueError:
            continue
        for it in od.get("items", []):
            if (it.get("sellerEmail") or "").lower() != seller_email:
                continue
            gross = float(it.get("price", 0)) * int(it.get("quantity", 1))
            earned += gross - gross * commission * (1 + gst_on_comm) - gross * tcs - gross * tds
    withdrawn = 0.0
    for p in db.collection("payout_requests").where("email", "==", seller_email).get():
        pd = p.to_dict()
        if pd.get("status") in ("pending", "approved", "paid", "on_hold"):
            withdrawn += float(pd.get("amount", 0))
    return round(max(earned - withdrawn, 0), 2)

@app.route("/api/v1/seller/payouts/request", methods=["POST"])
@seller_required
def request_payout():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        data = request.get_json()
        if not isinstance(data, dict): return jsonify({"error": "Invalid payload"}), 400
        amount = v_float(data.get("amount", 0), 1, 10_000_000, "amount")
        # SECURITY: previously any amount could be requested. Check against the seller's
        # real available balance (paid, delivered, past hold window, minus pending/paid payouts).
        available = compute_available_balance(request.seller_email)
        if amount > available:
            return jsonify({"error": "Amount exceeds available balance"}), 400
        pending = db.collection("payout_requests").where("email", "==", request.seller_email).where("status", "==", "pending").limit(1).get()
        if len(pending) > 0:
            return jsonify({"error": "You already have a pending payout request"}), 400

        _, doc_ref = db.collection("payout_requests").add({
            "email": request.seller_email,
            "brand": v_str(data.get("brand", "Unknown Brand"), 100, "brand"),
            "amount": amount,      
            "netPayable": amount,   
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "utr": ""
        })
        return jsonify({"status": "success", "id": doc_ref.id}), 201
    except Exception as e: 
        logger.error(f"Payout request error: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

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
            if not isinstance(data, dict): return jsonify({"error": "Invalid payload"}), 400
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
        logger.error(f"Error handling admin promocodes: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/promocodes/<doc_id>", methods=["PUT", "DELETE"])
@admin_required
def manage_promocode(doc_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        doc_ref = db.collection("promocodes").document(doc_id)
        if request.method == "PUT":
            update_data = request.get_json()
            if not isinstance(update_data, dict): return jsonify({"error": "Invalid payload"}), 400
            doc_ref.update({"status": update_data.get("status", "pending")})
            return jsonify({"status": "success"}), 200
        if request.method == "DELETE":
            doc_ref.delete()
            return jsonify({"status": "success"}), 200
    except Exception as e:
        logger.error(f"Error managing promocode {doc_id}: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

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
            if not isinstance(data, dict): return jsonify({"error": "Invalid payload"}), 400
            code = str(data.get("code", "")).strip().upper()
            if not PROMO_RE.match(code): return jsonify({"error": "Code must be 3-24 letters/numbers"}), 400
            promo_type = v_choice(data.get("type", "percentage"), {"percentage", "flat"}, "type")
            promo_value = v_float(data.get("value", 0), 1, 90 if promo_type == "percentage" else 100000, "value")

            existing = db.collection("promocodes").where("code", "==", code).get()
            if len(existing) > 0:
                return jsonify({"error": f"Promo code {code} is already taken!"}), 400

            promo_data = {
                "code": code,
                "type": promo_type,
                "value": promo_value,
                "creator_role": "seller",
                "seller_email": request.seller_email,
                "status": "pending", 
                "usage_limit": v_choice(data.get("usage_limit", "unlimited"), {"single", "unlimited"}, "usage limit"),
                "applicable_payment_method": v_choice(data.get("payment_method", "all"), {"all", "online", "cod"}, "payment method"),
                "valid_from": v_str(data.get("valid_from"), 40, "valid_from") or None,
                "valid_until": v_str(data.get("valid_until"), 40, "valid_until") or None,
                "used_by": [],
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            _, doc_ref = db.collection("promocodes").add(promo_data)
            return jsonify({"status": "success", "id": doc_ref.id}), 201
    except Exception as e:
        logger.error(f"Seller Promo Error: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

# ==========================================
# 10. CUSTOMER CHECKOUT PROMO VALIDATION
# ==========================================
@app.route("/api/v1/promocodes/validate", methods=["POST"])
def validate_promocode():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        data = request.get_json()
        if not isinstance(data, dict): return jsonify({"error": "Invalid payload"}), 400
        code = str(data.get("code", "")).strip().upper()
        if not PROMO_RE.match(code): return jsonify({"error": "Invalid promo code"}), 404
        user = optional_user()
        customer_email = user["email"].lower() if user else str(data.get("email", "")).strip().lower()

        query = db.collection("promocodes").where("code", "==", code).limit(1).get()
        if not query:
            return jsonify({"error": "Invalid promo code"}), 404

        promo = query[0].to_dict()

        if promo.get("status") != "active":
            return jsonify({"error": "Promo code is not active or awaiting approval"}), 400

        now = datetime.now(timezone.utc).isoformat()
        
        if promo.get("valid_from"):
            promo_start = promo.get("valid_from")
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
            # SECURITY: don't reveal seller emails to the public; send a brand name instead.
            "seller_brand": promo.get("seller_brand", "")
        }), 200
    except Exception as e:
        logger.error(f"Error validating promocode: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

# ==========================================
# 11. RUN THE SERVER
# ==========================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)