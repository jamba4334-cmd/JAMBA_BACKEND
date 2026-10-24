# ==========================================
# 1. IMPORTS
# ==========================================
import os
import sys
import json
import logging
import time
import hashlib
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from dotenv import load_dotenv

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import razorpay
import firebase_admin
from firebase_admin import credentials, firestore, auth as firebase_auth
import redis

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

# SECURITY: Rate Limiter Setup (Prevents DDoS and Brute Force)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per day", "100 per hour"],
    storage_uri=os.getenv("REDIS_URL", "memory://")
)

# CORS SETUP (Native Preflight Handling)
DEFAULT_ORIGINS = "http://localhost:5173,http://localhost:5174,https://jambawear.pages.dev,https://jamba-react.jamba4334.workers.dev"
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", DEFAULT_ORIGINS).split(",") if o.strip()]
CORS(app, resources={r"/*": {"origins": ALLOWED_ORIGINS}},
     allow_headers=["Authorization", "Content-Type", "Idempotency-Key"], 
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"], 
     supports_credentials=True, 
     max_age=600)

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  

ALLOWED_ADMIN_EMAIL = (os.getenv("ADMIN_EMAIL") or "").strip().lower()

# ==========================================
# INPUT VALIDATION HELPERS
# ==========================================
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,}$")
DOC_ID_RE = re.compile(r"^[A-Za-z0-9_\-@.]{1,128}$")
PROMO_RE = re.compile(r"^[A-Z0-9_-]{3,24}$")

class BadInput(ValueError): pass

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

def pick(data, allowed): return {k: data[k] for k in allowed if k in data}

PRODUCT_FIELDS = ["name", "description", "selling_price", "mrp", "category", "tribe", "images",
                  "sizes", "colors", "stock", "isReturnable", "brandName", "sellerName",
                  "sellerEmail", "item_id", "status", "tags", "hsn", "weight", "approval_status",
                  "isHidden", "isOutOfStock", "isDeleted", "blocked_reason"]
ORDER_ADMIN_FIELDS = ["status", "tracking_id", "courier", "admin_note", "delivered_at", "return_status"]
PAYOUT_ADMIN_FIELDS = ["status", "utr", "admin_note"]

@app.errorhandler(BadInput)
def handle_bad_input(e): return jsonify({"error": str(e)}), 400

@app.errorhandler(413)
def handle_too_large(_e): return jsonify({"error": "Request too large"}), 413

@app.errorhandler(404)
def handle_404(_e): return jsonify({"error": "Not found"}), 404

@app.errorhandler(429)
def handle_rate_limit(e):
    return jsonify({"error": f"Rate limit exceeded: {e.description}"}), 429

@app.errorhandler(Exception)
def handle_unexpected(e):
    logger.error("Unhandled error", exc_info=True)
    return jsonify({"error": "Internal server error"}), 500

# ==========================================
# 3. INITIALIZE SERVICES
# ==========================================
# Look for either environment variable to prevent Render crashes
FIREBASE_CONFIG_JSON = os.getenv("FIREBASE_CONFIG") or os.getenv("FIREBASE_CONFIG_JSON")
try:
    if not firebase_admin._apps:
        if FIREBASE_CONFIG_JSON:
            cred_dict = json.loads(FIREBASE_CONFIG_JSON)
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred)
            logger.info("✅ Firebase initialized successfully from Environment Variable.")
        else: logger.error("❌ FIREBASE_CONFIG_JSON is missing.")
    if firebase_admin._apps:
        db = firestore.client()
    else: db = None
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
        logger.warning("⚠️ Razorpay keys missing.")
        razorpay_client = None
except Exception as e:
    logger.error(f"❌ Razorpay failed: {e}")
    razorpay_client = None

try:
    redis_client = redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", 6379)),
        password=os.getenv("REDIS_PASSWORD", ""),
        ssl=True if os.getenv("REDIS_HOST") else False,
        decode_responses=True
    )
    logger.info("✅ Redis client initialized.")
except Exception as e:
    logger.error(f"❌ Redis initialization failed: {e}")
    redis_client = None

# ==========================================
# 4. SECURITY MIDDLEWARE & HEADERS
# ==========================================
@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Resource-Policy"] = "same-site"
    if request.path.startswith(("/admin", "/api/v1/seller", "/api/v1/customer")) or request.headers.get("Authorization"):
        response.headers["Cache-Control"] = "no-store"
    response.headers.pop("Server", None)
    return response

def _verify_bearer():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "): return None
    token = auth_header[7:].strip()
    if not token or len(token) > 4096: return None
    try:
        decoded = firebase_auth.verify_id_token(token, check_revoked=True)
    except Exception as e:
        logger.warning(f"Token verification failed: {e}")
        return None
    if not decoded.get("email"): return None
    return decoded

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "OPTIONS": return "", 200
        decoded = _verify_bearer()
        if not decoded: return jsonify({"error": "Unauthorized"}), 401
        email = decoded.get("email", "").lower()
        if db is None: return jsonify({"error": "Service unavailable"}), 503
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
        if request.method == "OPTIONS": return "", 200
        decoded = _verify_bearer()
        if not decoded: return jsonify({"error": "Unauthorized"}), 401
        if db is None: return jsonify({"error": "Service unavailable"}), 503
        email = decoded.get("email", "").lower()
        if not db.collection("authorized_sellers").document(email).get().exists: return jsonify({"error": "Forbidden"}), 403
        request.seller_email = email
        return f(*args, **kwargs)
    return decorated_function

def optional_user(): return _verify_bearer()

# ==========================================
# 5. PUBLIC STOREFRONT & CHECKOUT ROUTES
# ==========================================
@app.route("/health", methods=["GET"])
@limiter.exempt
def health(): return jsonify({"server": "running", "status": "ok"}), 200

@app.route("/api/v1/secure/upload-signature", methods=["GET"])
@limiter.limit("30 per minute")
def get_upload_signature():
    """Secure proxy for generating Cloudinary signatures with folder validation."""
    user = _verify_bearer()
    if not user: return jsonify({"error": "Unauthorized"}), 401
    
    purpose = request.args.get("purpose", "general").strip().lower()
    folder_map = {
        "kyc": "jamba_kyc",
        "review": "jamba_reviews",
        "product": "jamba_products",
        "storefront": "jamba_storefronts",
        "profile": "jamba_profiles",
        "site": "jamba_site"
    }
    folder = folder_map.get(purpose, "jamba_uploads")
    
    timestamp = int(time.time())
    api_secret = os.getenv("CLOUDINARY_API_SECRET")
    api_key = os.getenv("CLOUDINARY_API_KEY") or os.getenv("VITE_CLOUDINARY_API_KEY", "")
    cloud_name = os.getenv("CLOUDINARY_CLOUD_NAME") or os.getenv("VITE_CLOUDINARY_CLOUD_NAME", "dbbafwgug")
    
    if not api_secret:
        return jsonify({"error": "Storage configuration missing"}), 500
        
    # Cloudinary requires parameters in alphabetical order: folder, then timestamp
    to_sign = f"folder={folder}&timestamp={timestamp}{api_secret}"
    signature = hashlib.sha1(to_sign.encode("utf-8")).hexdigest()
    
    return jsonify({
        "signature": signature,
        "timestamp": timestamp,
        "folder": folder,
        "api_key": api_key,
        "cloud_name": cloud_name
    }), 200

@app.route("/api/v1/public/settings/financial", methods=["GET"])
@limiter.limit("60 per minute")
def public_financial_settings():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        doc = db.collection("settings").document("financial_settings").get()
        return jsonify(doc.to_dict() if doc.exists else {}), 200
    except Exception as e:
        logger.error(f"Error fetching public settings: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/v1/public/settings/<setting_id>", methods=["GET"])
@limiter.limit("60 per minute")
def get_public_setting(setting_id):
    """Serves public layout/banner settings such as hero_banners for Navbar.jsx."""
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        clean_id = v_doc_id(setting_id, "setting_id")
        doc = db.collection("settings").document(clean_id).get()
        return jsonify(doc.to_dict() if doc.exists else {}), 200
    except Exception as e:
        logger.error(f"Error fetching public setting {setting_id}: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

storefront_cache = {"data": {}, "timestamp": 0}
CACHE_DURATION = 3600  

@app.route('/api/v1/public/storefronts', methods=['GET'])
@limiter.limit("50 per minute")
def get_public_storefronts():
    current_time = time.time()
    if current_time - storefront_cache["timestamp"] < CACHE_DURATION and storefront_cache["data"]:
        return jsonify(storefront_cache["data"]), 200
    try:
        if db is None: return jsonify({"error": "Database unavailable"}), 503
        profiles_ref = db.collection('seller_profiles').stream()
        profiles_map = {}
        for doc in profiles_ref:
            data = doc.to_dict()
            storefront = data.get('storefront', {})
            handle = storefront.get('vanityHandle', '').lower()
            if handle:
                profiles_map[handle] = {
                    "brandLogo": storefront.get('brandLogo', ''),
                    "brandName": storefront.get('brandName', ''),
                    "vanityHandle": handle
                }
        storefront_cache["data"] = profiles_map
        storefront_cache["timestamp"] = current_time
        return jsonify(profiles_map), 200
    except Exception as e:
        logger.error(f"Error fetching storefronts: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/public/storefront/<handle>', methods=['GET'])
@limiter.limit("30 per minute")
def get_single_storefront(handle):
    try:
        if db is None: return jsonify({"error": "Database unavailable"}), 503
        profiles_ref = db.collection('seller_profiles').stream()
        for doc in profiles_ref:
            data = doc.to_dict()
            storefront = data.get('storefront', {})
            doc_handle = storefront.get('vanityHandle', '').lower()
            if doc_handle == handle.lower():
                response_data = storefront.copy()
                response_data["sellerEmail"] = doc.id
                return jsonify(response_data), 200
        return jsonify({"error": "Storefront not found"}), 404
    except Exception as e:
        logger.error(f"Error fetching storefront {handle}: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/create-order", methods=["POST"])
@limiter.limit("5 per minute")
def create_order():
    if db is None: return jsonify({"error": "Service temporarily unavailable."}), 503
    
    idempotency_key = request.headers.get("Idempotency-Key")
    if idempotency_key:
        existing_req = db.collection("idempotency_logs").document(idempotency_key).get()
        if existing_req.exists:
            return jsonify(existing_req.to_dict().get("response")), 201

    try:
        data = request.get_json()
        if not data or not isinstance(data, dict): return jsonify({"error": "Invalid payload."}), 400
        cart = data.get("cart")
        if not isinstance(cart, list) or len(cart) == 0: return jsonify({"error": "Cart empty."}), 400
        if len(cart) > 50: return jsonify({"error": "Too many items."}), 400

        user = optional_user()
        customer_email = user["email"].lower() if user else v_email(data.get("customer"), "customer email")
        customer_uid = user["uid"] if user else None
        raw_addr = data.get("shippingAddress", {})
        if not isinstance(raw_addr, dict): raw_addr = {}
        shipping_address = {k: v_str(raw_addr.get(k, ""), 200, k) for k in ["name", "phone", "line1", "line2", "city", "state", "pincode", "landmark"]}
            
        payment_method = "COD" if str(data.get("payment_method", "Razorpay")).strip().upper() == "COD" else "Razorpay"
        promo_code_str = str(data.get("promo_code", data.get("promo_used", ""))).strip().upper()

        config_doc = db.collection("settings").document("financial_settings").get()
        config = config_doc.to_dict() if config_doc.exists else {}
        free_shipping_min = float(config.get("shippingFreeThreshold", 1999.0))
        default_shipping_fee = float(config.get("defaultShippingFee", 149.0))
        cod_convenience_fee = float(config.get("codConvenienceFee", 39.0))
        raw_brackets = config.get("gstBrackets", [{"maxLimit": 2500, "rate": 5.0}, {"maxLimit": 999999, "rate": 18.0}])
        gst_brackets = sorted(raw_brackets, key=lambda x: float(x.get("maxLimit", 999999)))

        promo_data = None
        promo_doc_id = None
        if promo_code_str:
            promo_query = db.collection("promocodes").where("code", "==", promo_code_str).where("status", "==", "active").limit(1).get()
            if promo_query:
                temp_promo = promo_query[0].to_dict()
                now = datetime.now(timezone.utc).isoformat()
                is_valid_time = True
                if temp_promo.get("valid_from"):
                    promo_start = temp_promo.get("valid_from")
                    if not promo_start.endswith("Z") and "+" not in promo_start: promo_start += "+05:30"
                    if now < promo_start: is_valid_time = False
                if temp_promo.get("valid_until"):
                    promo_end = temp_promo.get("valid_until")
                    if not promo_end.endswith("Z") and "+" not in promo_end: promo_end += "+05:30" 
                    if now > promo_end: is_valid_time = False
                is_valid_usage = True
                if temp_promo.get("usage_limit") == "single" and customer_email in temp_promo.get("used_by", []): is_valid_usage = False
                
                promo_payment_method = temp_promo.get("applicable_payment_method", "all")
                if promo_payment_method == "online" and payment_method == "COD": return jsonify({"error": "Promo is strictly for Online Orders."}), 400
                if promo_payment_method == "cod" and payment_method != "COD": return jsonify({"error": "Promo valid for COD only."}), 400
                if is_valid_time and is_valid_usage:
                    promo_data = temp_promo
                    promo_doc_id = promo_query[0].id

        secure_subtotal = 0
        seller_eligible_subtotal = 0
        enriched_cart = []
        seller_emails_set = set()

        for item in cart:
            if not isinstance(item, dict): return jsonify({"error": "Invalid item."}), 400
            item_id = v_doc_id(item.get("id") or item.get("item_id"), "product id")
            quantity = v_int(item.get("quantity", 1), 1, 20, "quantity")
            
            doc_ref = db.collection("products").document(item_id).get()
            if not doc_ref.exists:
                query = db.collection("products").where("item_id", "==", item_id).limit(1).get()
                if not query: return jsonify({"error": "Product out of stock."}), 400
                product = query[0].to_dict()
            else: product = doc_ref.to_dict()

            available_stock = int(product.get("stock", 0) or product.get("available_stock", 0))
            if available_stock < quantity and not product.get("made_to_order", False):
                return jsonify({"error": f"Not enough stock for {product.get('name', product.get('title', 'Product'))}. Only {available_stock} left."}), 400

            real_price = float(product.get("selling_price", 0))
            effective_gst_rate = 18.0 
            for bracket in gst_brackets:
                if real_price <= float(bracket.get("maxLimit", 999999)):
                    effective_gst_rate = float(bracket.get("rate", 18.0))
                    break

            item_total = real_price * quantity
            secure_subtotal += item_total
            
            seller_email = product.get("sellerEmail", "")
            if seller_email: seller_emails_set.add(seller_email)
            if promo_data and promo_data.get("creator_role") == "seller" and promo_data.get("seller_email") == seller_email:
                seller_eligible_subtotal += item_total

            product_images = product.get("images", [])
            primary_image = product_images[0] if isinstance(product_images, list) and len(product_images) > 0 else ""

            enriched_cart.append({
                "id": item_id, 
                "quantity": quantity, 
                "size": v_str(item.get("size", ""), 20, "size"),
                "color": v_str(item.get("color", ""), 40, "color"), 
                "name": product.get("name", product.get("title", "")),
                "price": real_price, 
                "brandName": product.get("brandName", "JAMBA WEAR"), 
                "sellerName": product.get("sellerName", ""),
                "sellerEmail": seller_email, 
                "isReturnable": product.get("isReturnable", True), 
                "return_policy": product.get("return_policy", "7_day_return_replace"),
                "hsn": product.get("hsn", "6204"),
                "applied_gst_rate": effective_gst_rate,
                "image": primary_image
            })

        total_discount = 0.0
        if promo_data:
            discount_value = float(promo_data.get("value", 0))
            if promo_data.get("creator_role") == "admin":
                total_discount = secure_subtotal * (discount_value / 100.0) if promo_data.get("type") == "percentage" else min(discount_value, secure_subtotal)
            elif promo_data.get("creator_role") == "seller":
                total_discount = seller_eligible_subtotal * (discount_value / 100.0) if promo_data.get("type") == "percentage" else min(discount_value, seller_eligible_subtotal)

        taxable_value = secure_subtotal - total_discount
        total_gst = 0.0
        for item in enriched_cart:
            item_ratio = (item["price"] * item["quantity"]) / secure_subtotal if secure_subtotal > 0 else 0
            item_net = (item["price"] * item["quantity"]) - (total_discount * item_ratio)
            total_gst += item_net - (item_net / (1 + (item["applied_gst_rate"] / 100.0)))

        calculated_shipping = 0.0 if taxable_value >= free_shipping_min else default_shipping_fee
        extra_cod = cod_convenience_fee if payment_method == "COD" else 0.0
        final_total = max(taxable_value + calculated_shipping + extra_cod, 0)
        if final_total <= 0 or final_total > 1_000_000: return jsonify({"error": "Invalid order total."}), 400
            
        unique_jamba_id = "JB" + datetime.now(timezone.utc).strftime("%y%m%d") + uuid.uuid4().hex[:6].upper()

        order_data = {
            "jamba_order_id": unique_jamba_id, "email": customer_email, "userId": customer_uid, "items": enriched_cart,
            "subtotal": secure_subtotal, "discount_applied": total_discount, "promo_used": promo_code_str if total_discount > 0 else None,
            "promo_creator_role": promo_data.get("creator_role") if promo_data else None, "promo_seller_email": promo_data.get("seller_email") if promo_data else None,
            "taxable_value": taxable_value, "total_gst": round(total_gst, 2), "shipping_fee": calculated_shipping, "cod_fee": extra_cod,
            "total": final_total, "status": "pending", "payment_method": payment_method, "shippingAddress": shipping_address,
            "created_at": datetime.now(timezone.utc).isoformat(), "sellerEmails": list(seller_emails_set)
        }

        if total_discount > 0 and promo_data and promo_data.get("usage_limit") == "single":
            if payment_method == "COD":
                db.collection("promocodes").document(promo_doc_id).update({"used_by": firestore.ArrayUnion([customer_email])})

        response_payload = {}

        if payment_method == "COD":
            order_data["status"] = "processing"
            order_data["order_id"] = f"cod_{int(datetime.now().timestamp())}"
            db.collection("orders").add(order_data)
            response_payload = {"status": "success", "payment_method": "COD", "order_id": order_data["jamba_order_id"]}
        else:
            if not razorpay_client: return jsonify({"error": "Payment gateway unavailable"}), 503
            razorpay_order = razorpay_client.order.create({"amount": int(final_total * 100), "currency": "INR", "receipt": f"rcpt_{int(datetime.now().timestamp())}"})
            order_data["razorpay_order_id"] = razorpay_order["id"]
            db.collection("orders").add(order_data)
            response_payload = razorpay_order

        if idempotency_key:
            db.collection("idempotency_logs").document(idempotency_key).set({
                "response": response_payload, "created_at": datetime.now(timezone.utc).isoformat()
            })

        return jsonify(response_payload), 201

    except ValueError as ve: return jsonify({"error": "Invalid format."}), 400
    except Exception as e:
        logger.error(f"Critical error: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error."}), 500

@app.route("/verify-payment", methods=["POST"])
def verify_payment():
    if db is None: return jsonify({"error": "Database unavailable."}), 503
    if not razorpay_client: return jsonify({"error": "Payment gateway unavailable."}), 503
    try:
        data = request.get_json()
        if not data: return jsonify({"error": "Invalid payload."}), 400
        razorpay_order_id = v_str(data.get("razorpay_order_id"), 64, "order id")
        rose_payment_id = v_str(data.get("razorpay_payment_id"), 64, "payment id")
        razorpay_signature = v_str(data.get("razorpay_signature"), 128, "signature")
        if not (razorpay_order_id and rose_payment_id and razorpay_signature): return jsonify({"error": "Invalid payload."}), 400

        razorpay_client.utility.verify_payment_signature({
            "razorpay_order_id": razorpay_order_id, 
            "razorpay_payment_id": rose_payment_id, 
            "razorpay_signature": razorpay_signature
        })
        
        orders_ref = db.collection("orders").where("razorpay_order_id", "==", razorpay_order_id).limit(1).get()
        if not orders_ref:
            return jsonify({"error": "Order not found."}), 404
            
        order_doc = orders_ref[0]
        order_data = order_doc.to_dict()
        
        if order_data.get("status") == "paid":
            return jsonify({"status": "Payment already verified!"}), 200

        db.collection("orders").document(order_doc.id).update({
            "status": "paid", 
            "payment_id": rose_payment_id,
            "paid_at": datetime.now(timezone.utc).isoformat()
        })

        promo_code_str = order_data.get("promo_used")
        customer_email = order_data.get("email")
        if promo_code_str and customer_email:
            promo_query = db.collection("promocodes").where("code", "==", promo_code_str).limit(1).get()
            if promo_query:
                promo_doc = promo_query[0]
                if promo_doc.to_dict().get("usage_limit") == "single":
                    db.collection("promocodes").document(promo_doc.id).update({
                        "used_by": firestore.ArrayUnion([customer_email])
                    })
                    
        return jsonify({"status": "Payment verified and saved!"}), 200
        
    except razorpay.errors.SignatureVerificationError: 
        return jsonify({"error": "Invalid signature."}), 400
    except Exception as e:
        logger.error(f"Error in verify_payment: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error."}), 500

@app.route("/api/orders/<order_id>/invoice", methods=["GET"])
def generate_invoice(order_id):
    if db is None: return jsonify({"error": "Service unavailable"}), 503
    try:
        order_id = v_doc_id(order_id, "order id")
        user = optional_user()
        if not user: return jsonify({"error": "Unauthorized"}), 401
        
        order_doc = db.collection("orders").document(order_id).get()
        if not order_doc.exists: return jsonify({"error": "Order not found"}), 404
        order_data = order_doc.to_dict()
        
        req_email = user.get("email", "").lower()
        
        is_owner = order_data.get("userId") == user.get("uid") or (order_data.get("email") or "").lower() == req_email
        is_seller = req_email in [e.lower() for e in order_data.get("sellerEmails", [])]
        
        is_admin = False
        if req_email:
            if ALLOWED_ADMIN_EMAIL and req_email == ALLOWED_ADMIN_EMAIL: is_admin = True
            else:
                admin_doc = db.collection("admin_users").document(req_email).get()
                if admin_doc.exists and admin_doc.to_dict().get("isAuthorized") is True: is_admin = True

        if not (is_owner or is_seller or is_admin): 
            return jsonify({"error": "Unauthorized to view this invoice"}), 403

        seller_emails = order_data.get("sellerEmails", [])
        seller_email = seller_emails[0] if seller_emails else ""
        seller_data = {}
        if seller_email:
            seller_doc = db.collection("authorized_sellers").document(seller_email).get()
            if seller_doc.exists: seller_data = seller_doc.to_dict()
                
        kyc_data = seller_data.get("kycData", {})
        has_gst = kyc_data.get("hasGst", False)
        document_title = "TAX INVOICE" if has_gst else "BILL OF SUPPLY"
        
        brand_name = seller_data.get("brandName", "Jambawear Artisan")
        seller_name = seller_data.get("sellerName", "Registered Artisan")
        seller_state = seller_data.get("pickupState", seller_data.get("state", "Assam")).strip().upper()
        seller_gst = kyc_data.get("gstNumber", "UNREGISTERED")
        seller_pan = kyc_data.get("panNumber", "N/A")
        seller_address = seller_data.get("pickupAddress", seller_data.get("address", ""))

        shipping = order_data.get("shippingAddress", {})
        customer_name = shipping.get("name", order_data.get("email", "Customer"))
        customer_state = shipping.get("state", "Assam").strip().upper()
        
        is_intra_state = (seller_state == customer_state)

        def safe_text(text):
            return str(text).encode('latin-1', 'replace').decode('latin-1')

        pdf = FPDF(orientation="P", unit="mm", format="A4")
        pdf.add_page()
        pdf.set_draw_color(200, 200, 200)

        pdf.set_font("Arial", 'B', 22)
        pdf.set_text_color(139, 115, 85)
        pdf.cell(100, 8, txt="JAMBA WEAR", ln=False, align='L')
        
        pdf.set_font("Arial", 'B', 16)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(90, 8, txt=safe_text(document_title), ln=True, align='R')
        
        pdf.set_font("Arial", '', 9)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(190, 5, txt="Authentic Traditional Fashion Marketplace", ln=True, align='L')
        pdf.ln(4)

        pdf.set_fill_color(248, 249, 250)
        pdf.set_text_color(50, 50, 50)
        pdf.set_font("Arial", '', 8)
        eco_text = "Facilitated By: JAMBA WEAR PRIVATE LIMITED | Reg. Office: Guwahati, Assam, 781001 | GSTIN: 18AAACJ0000A1Z5\n* TCS under Section 52 of the CGST Act is discharged on this transaction."
        pdf.multi_cell(190, 5, txt=safe_text(eco_text), border=1, align='C', fill=True)
        pdf.ln(6)

        pdf.set_font("Arial", 'B', 9)
        pdf.set_text_color(0, 0, 0)
        invoice_num = f"JW/{order_data.get('jamba_order_id', order_id)[-8:]}"
        
        pdf.cell(95, 5, txt=safe_text(f"Invoice No: {invoice_num}"), ln=False)
        pdf.cell(95, 5, txt=safe_text(f"Date: {order_data.get('created_at', '')[:10]}"), ln=True, align='R')
        pdf.cell(95, 5, txt=safe_text(f"Order Ref: #{order_data.get('jamba_order_id', order_id)}"), ln=False)
        pdf.cell(95, 5, txt=safe_text(f"Place of Supply: {customer_state}"), ln=True, align='R')
        pdf.ln(6)

        pdf.set_fill_color(235, 235, 235)
        pdf.set_font("Arial", 'B', 9)
        pdf.cell(92, 7, txt=" Sold By (Seller Details):", border=1, fill=True, ln=False)
        pdf.cell(6, 7, txt="", border=0, ln=False)
        pdf.cell(92, 7, txt=" Billed & Shipped To:", border=1, fill=True, ln=True)

        pdf.set_font("Arial", '', 9)
        
        seller_block = f"{brand_name} (Prop: {seller_name})\n{seller_address}\nState: {seller_state}\nPAN: {seller_pan}\n"
        seller_block += f"GSTIN: {seller_gst}" if has_gst else "GST: UNREGISTERED"

        buyer_block = f"{customer_name}\n{shipping.get('address1', '')} {shipping.get('landmark', '')}\n{shipping.get('city', '')}, {customer_state} - {shipping.get('pincode', '')}\nPhone: {shipping.get('phone', 'N/A')}"

        x_start = pdf.get_x()
        y_start = pdf.get_y()
        pdf.multi_cell(92, 5, txt=safe_text(seller_block), border=1)
        y_seller = pdf.get_y()
        
        pdf.set_xy(x_start + 98, y_start)
        pdf.multi_cell(92, 5, txt=safe_text(buyer_block), border=1)
        y_buyer = pdf.get_y()
        
        pdf.set_y(max(y_seller, y_buyer) + 8)

        pdf.set_font("Arial", 'B', 8)
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(10, 8, txt="#", border=1, align='C', fill=True)
        pdf.cell(75, 8, txt="Item Description & HSN", border=1, align='L', fill=True)
        pdf.cell(15, 8, txt="Qty", border=1, align='C', fill=True)
        pdf.cell(25, 8, txt="Taxable (Rs)", border=1, align='R', fill=True)
        pdf.cell(35, 8, txt="Tax Breakdown", border=1, align='C', fill=True)
        pdf.cell(30, 8, txt="Total (Rs)", border=1, align='R', fill=True)
        pdf.ln(8)

        pdf.set_font("Arial", '', 8)
        
        items = order_data.get("items", [])
        subtotal = float(order_data.get("subtotal", 0))
        discount = float(order_data.get("discount_applied", 0))
        total_taxable = 0.0
        
        for idx, item in enumerate(items):
            item_name = str(item.get("name", item.get("title", "")))[:40]
            hsn = item.get("hsn", "6204")
            qty = int(item.get("quantity", 1))
            price = float(item.get('price', 0))
            gross = price * qty
            
            item_discount = (gross / subtotal) * discount if subtotal > 0 else 0
            net_amount = max(0, gross - item_discount)
            
            if has_gst:
                rate = 18.0 if net_amount > 2500 else 5.0
                taxable = net_amount / (1 + (rate / 100))
                tax_val = net_amount - taxable
                total_taxable += taxable
                
                if is_intra_state:
                    tax_str = f"CGST: {tax_val/2:.2f}\nSGST: {tax_val/2:.2f}"
                else:
                    tax_str = f"IGST ({rate}%): {tax_val:.2f}"
            else:
                taxable = net_amount
                total_taxable += taxable
                tax_str = "GST: 0.00"

            desc_str = f"{item_name}\nSize: {item.get('size', 'N/A')} | HSN: {hsn}"
            lines = max(desc_str.count('\n') + 1, tax_str.count('\n') + 1)
            row_h = lines * 5

            x_curr = pdf.get_x()
            y_curr = pdf.get_y()
            
            pdf.cell(10, row_h, txt=str(idx+1), border=1, align='C')
            pdf.set_xy(x_curr + 10, y_curr)
            pdf.multi_cell(75, 5, txt=safe_text(desc_str), border=1)
            
            pdf.set_xy(x_curr + 85, y_curr)
            pdf.cell(15, row_h, txt=str(qty), border=1, align='C')
            pdf.cell(25, row_h, txt=safe_text(f"{taxable:.2f}"), border=1, align='R')
            
            pdf.set_xy(x_curr + 125, y_curr)
            pdf.multi_cell(35, row_h / (tax_str.count('\n')+1), txt=safe_text(tax_str), border=1, align='C')
            
            pdf.set_xy(x_curr + 160, y_curr)
            pdf.cell(30, row_h, txt=safe_text(f"{net_amount:.2f}"), border=1, align='R')
            
            pdf.set_y(y_curr + row_h)

        shipping_fee = float(order_data.get("shipping_fee", 0))
        if shipping_fee > 0:
            pdf.cell(10, 8, txt="-", border=1, align='C')
            pdf.cell(75, 8, txt="Shipping & Handling (SAC: 996511)", border=1)
            pdf.cell(15, 8, txt="1", border=1, align='C')
            pdf.cell(25, 8, txt=safe_text(f"{shipping_fee:.2f}"), border=1, align='R')
            pdf.cell(35, 8, txt="GST: 0.00", border=1, align='C')
            pdf.cell(30, 8, txt=safe_text(f"{shipping_fee:.2f}"), border=1, align='R')
            pdf.ln(8)
            total_taxable += shipping_fee

        pdf.ln(4)
        x_sum = 120
        y_sum = pdf.get_y()
        
        pdf.set_font("Arial", '', 8)
        pdf.set_text_color(100, 100, 100)
        decl = "Tax Payable on Reverse Charge: No\n\n"
        if has_gst: decl += "We declare that this invoice shows the actual price of\nthe goods described and that all particulars are correct."
        else: decl += "Issued by an unregistered artisan under GST exemptions.\nNo GST is charged or collected."
        pdf.multi_cell(100, 4, txt=safe_text(decl))
        
        pdf.set_xy(x_sum, y_sum)
        pdf.set_text_color(0, 0, 0)
        
        def print_total_row(label, val, bold=False, color=None):
            if bold: pdf.set_font("Arial", 'B', 10)
            else: pdf.set_font("Arial", '', 9)
            if color: pdf.set_text_color(*color)
            pdf.set_x(x_sum)
            pdf.cell(40, 6, txt=label, border=0, align='L')
            pdf.cell(30, 6, txt=safe_text(f"Rs. {val:.2f}"), border=0, align='R')
            if color: pdf.set_text_color(0, 0, 0)
            pdf.ln(6)

        print_total_row("Total Taxable Value:", total_taxable)
        
        total_gst = float(order_data.get('total_gst', 0))
        if has_gst and total_gst > 0:
            if is_intra_state:
                print_total_row("CGST Apportioned:", total_gst / 2)
                print_total_row("SGST Apportioned:", total_gst / 2)
            else:
                print_total_row("IGST Apportioned:", total_gst)
                
        if discount > 0:
            print_total_row("Total Discount:", -discount, color=(5, 150, 105))
            
        pdf.set_y(pdf.get_y() + 2)
        pdf.set_x(x_sum)
        pdf.cell(70, 0, border="T")
        pdf.ln(1)
        
        print_total_row("GRAND TOTAL:", float(order_data.get('total', 0)), bold=True)
        
        pdf.set_x(x_sum)
        pdf.cell(70, 0, border="B")

        pdf.ln(20)
        pdf.set_font("Arial", 'I', 8)
        pdf.cell(100, 4, txt="E. & O.E.", ln=False)
        pdf.set_font("Arial", 'B', 9)
        pdf.cell(90, 4, txt=safe_text(f"For {brand_name}"), ln=True, align='R')
        pdf.ln(8)
        pdf.set_font("Arial", '', 8)
        pdf.cell(190, 4, txt="Authorized Signatory", ln=True, align='R')

        pdf_out = pdf.output(dest='S')
        pdf_bytes = pdf_out.encode('latin1') if isinstance(pdf_out, str) else bytes(pdf_out)

        return send_file(
            io.BytesIO(pdf_bytes), 
            mimetype='application/pdf', 
            as_attachment=False, 
            download_name=f"Invoice_{order_id}.pdf"
        )
    except Exception as e:
        logger.error(f"Invoice failed: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to generate document"}), 500

# ==========================================
# 6. ADMIN ROUTES & SESSION CONTROL
# ==========================================
@app.route("/api/v1/admin/session", methods=["POST", "DELETE"])
@admin_required
def manage_admin_session():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    admin_email = request.admin_email
    admin_ref = db.collection("admin_users").document(admin_email)
    now = datetime.now(timezone.utc).isoformat()
    
    if request.method == "POST":
        ip_address = get_remote_address()
        admin_ref.set({
            "isOnline": True,
            "lastActive": now,
            "lastIp": ip_address,
            "forceLogout": False
        }, merge=True)
        db.collection("admin_audit_logs").add({
            "email": admin_email,
            "action": "LOGIN",
            "timestamp": now,
            "ip": ip_address,
            "details": "Admin logged in securely."
        })
        return jsonify({"status": "Session started"}), 200
        
    elif request.method == "DELETE":
        admin_ref.set({"isOnline": False, "lastActive": now}, merge=True)
        db.collection("admin_audit_logs").add({
            "email": admin_email,
            "action": "LOGOUT",
            "timestamp": now,
            "ip": get_remote_address(),
            "details": "Admin logged out."
        })
        return jsonify({"status": "Session ended"}), 200

@app.route("/api/v1/admin/session/status", methods=["GET"])
@admin_required
def admin_session_status():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    admin_email = request.admin_email
    
    if ALLOWED_ADMIN_EMAIL and admin_email == ALLOWED_ADMIN_EMAIL:
        return jsonify({"isAuthorized": True, "forceLogout": False}), 200
        
    admin_doc = db.collection("admin_users").document(admin_email).get()
    if not admin_doc.exists:
        return jsonify({"isAuthorized": False, "forceLogout": True}), 403
        
    data = admin_doc.to_dict()
    if data.get("forceLogout") is True or data.get("isAuthorized") is not True:
        return jsonify({"isAuthorized": False, "forceLogout": True}), 403
        
    db.collection("admin_users").document(admin_email).update({
        "lastActive": datetime.now(timezone.utc).isoformat()
    })
    return jsonify({"isAuthorized": True, "forceLogout": False}), 200

@app.route("/admin/products", methods=["GET", "POST"])
@admin_required
def admin_products():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    if request.method == "GET":
        try:
            products = [{**doc.to_dict(), "docId": doc.id} for doc in db.collection("products").order_by("created_at", direction=firestore.Query.DESCENDING).limit(v_int(request.args.get("limit", 50), 1, 200, "limit")).get()]
            return jsonify(products), 200
        except Exception as e: return jsonify({"error": "Internal server error"}), 500
    if request.method == "POST":
        try:
            data = pick(request.get_json(), PRODUCT_FIELDS)
            if "selling_price" in data: data["selling_price"] = v_float(data["selling_price"], 1, 1_000_000, "price")
            
            now = datetime.now(timezone.utc).isoformat()
            data.update({
                "created_at": now, 
                "created_by": request.admin_email,
                "audit_history": [{
                    "action": "created",
                    "timestamp": now,
                    "actor_role": "admin",
                    "actor_id": request.admin_email,
                    "details": "Product uploaded by admin"
                }]
            })
            _, doc_ref = db.collection("products").add(data)
            return jsonify({"status": "success", "id": doc_ref.id}), 201
        except Exception as e: return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/products/<doc_id>", methods=["PUT", "DELETE"])
@admin_required
def admin_product_detail(doc_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        doc_ref = db.collection("products").document(v_doc_id(doc_id))
        if request.method == "PUT":
            data = pick(request.get_json(), PRODUCT_FIELDS)
            if "selling_price" in data: data["selling_price"] = v_float(data["selling_price"], 1, 1_000_000, "price")
            if not data: return jsonify({"error": "No valid fields"}), 400
            
            action = "edited"
            details = "Admin updated product details"
            reason = data.get("blocked_reason")

            if "isDeleted" in data:
                action = "soft_delete" if data["isDeleted"] else "restore"
                details = f"Admin {'archived' if data['isDeleted'] else 'restored'} the product"
            elif data.get("approval_status") == "blocked":
                action = "blocked"
                details = "Admin blocked the product"
            elif data.get("approval_status") == "approved":
                action = "approved"
                details = "Admin approved the product"
            elif "isHidden" in data:
                action = "edited"
                details = f"Admin made product {'hidden' if data['isHidden'] else 'visible'}"
            elif "isOutOfStock" in data:
                action = "edited"
                details = f"Admin marked product as {'Out of Stock' if data['isOutOfStock'] else 'In Stock'}"

            audit_entry = {
                "action": action,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actor_role": "admin",
                "actor_id": request.admin_email,
                "details": details
            }
            if reason: audit_entry["reason"] = reason

            update_payload = {**data, "audit_history": firestore.ArrayUnion([audit_entry])}
            doc_ref.update(update_payload)
            return jsonify({"status": "success"}), 200
            
        if request.method == "DELETE":
            doc_ref.delete()
            return jsonify({"status": "success"}), 200
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/orders", methods=["GET"])
@admin_required
def admin_orders():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        return jsonify([{**doc.to_dict(), "id": doc.id} for doc in db.collection("orders").order_by("created_at", direction=firestore.Query.DESCENDING).limit(int(request.args.get("limit", 50))).get()]), 200
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/orders/<order_id>", methods=["PUT"])
@admin_required
def update_order(order_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        data = pick(request.get_json(), ORDER_ADMIN_FIELDS)
        if not data: return jsonify({"error": "No valid fields"}), 400
        data["updated_by"] = request.admin_email
        db.collection("orders").document(v_doc_id(order_id)).update(data)
        return jsonify({"status": "success"}), 200
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/orders/<order_id>/force-clear", methods=["POST"])
@admin_required
def force_clear_order(order_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        db.collection("orders").document(order_id).update({"status": "settled_override"})
        return jsonify({"status": "success", "message": "Escrow released manually."}), 200
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/customers", methods=["GET"])
@admin_required
def admin_customers():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try: return jsonify([{**doc.to_dict(), "id": doc.id} for doc in db.collection("users").limit(int(request.args.get("limit", 50))).get()]), 200
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/settings/<doc_id>", methods=["GET", "PUT"])
@admin_required
def admin_settings(doc_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    doc_id = v_doc_id(doc_id, "settings id")
    try:
        if request.method == "GET":
            doc = db.collection("settings").document(doc_id).get()
            return jsonify(doc.to_dict() if doc.exists else ({"tribes": []} if doc_id == "tribe_categories" else {})), 200
        if request.method == "PUT":
            data = request.get_json()
            if not isinstance(data, dict): return jsonify({"error": "Invalid payload"}), 400
            if doc_id == "tribe_categories": data["last_updated"] = datetime.now(timezone.utc).isoformat()
            db.collection("settings").document(doc_id).set(data, merge=True)
            return jsonify({"status": "Settings updated"}), 200
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/sellers", methods=["GET", "POST"])
@admin_required
def admin_sellers():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        if request.method == "GET":
            sellers = []
            for doc in db.collection("authorized_sellers").get():
                sdata = {**doc.to_dict(), "id": doc.id}
                pdoc = db.collection("seller_profiles").document(doc.id).get()
                sdata["profile"] = pdoc.to_dict() if pdoc.exists else {}
                sellers.append(sdata)
            return jsonify(sellers), 200
        if request.method == "POST":
            email = v_email(request.get_json().get("email"))
            db.collection("authorized_sellers").document(email).set({"email": email, "addedAt": datetime.now(timezone.utc).isoformat(), "addedBy": request.admin_email}, merge=True)
            return jsonify({"status": "Seller authorized"}), 201
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/sellers/<email>", methods=["DELETE"])
@admin_required
def remove_seller(email):
    try:
        db.collection("authorized_sellers").document(v_email(email)).delete()
        return jsonify({"status": "Seller removed"}), 200
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/seller_profiles/<email>", methods=["GET", "PUT"])
@admin_required
def admin_seller_profile(email):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        profile_ref = db.collection("seller_profiles").document(v_email(email))
        if request.method == "GET": return jsonify(profile_ref.get().to_dict() if profile_ref.get().exists else {}), 200
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get("storefront"), dict): return jsonify({"error": "Invalid request"}), 400
        profile_ref.set({"storefront": data["storefront"], "updated_at": datetime.now(timezone.utc).isoformat()}, merge=True)
        return jsonify({"status": "Profile updated"}), 200
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

# ==========================================
# 7. ADMIN FINANCE & LEDGERS
# ==========================================
@app.route("/admin/payouts", methods=["GET"])
@admin_required
def admin_payouts():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        q = db.collection("payout_requests")
        if request.args.get("status"): q = q.where("status", "==", request.args.get("status"))
        if request.args.get("email"): q = q.where("email", "==", request.args.get("email"))
        return jsonify([{**doc.to_dict(), "id": doc.id} for doc in q.get()]), 200
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/finance/customer-payments", methods=["GET"])
@admin_required
def admin_customer_payments():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        payments = []
        for doc in db.collection("orders").order_by("created_at", direction=firestore.Query.DESCENDING).limit(int(request.args.get("limit", 100))).get():
            o = doc.to_dict()
            payments.append({"id": doc.id, "order_id": o.get("jamba_order_id", "N/A"), "customer": o.get("email", "Guest"), "amount": o.get("total", 0), "method": "COD" if o.get("payment_method", "Online").upper() == "COD" else "Online", "status": o.get("status", "pending"), "date": datetime.fromisoformat(o.get("created_at")).strftime("%d %b %Y") if o.get("created_at") else "Unknown"})
        return jsonify(payments), 200
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/finance/kpis", methods=["GET"])
@admin_required
def admin_finance_kpis():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        pending_payouts = sum([float(doc.to_dict().get("amount", doc.to_dict().get("netPayable", 0))) for doc in db.collection("payout_requests").where("status", "==", "pending").get()])
        in_escrow = sum([float(doc.to_dict().get("total", 0)) for doc in db.collection("orders").where("status", "==", "paid").get()])
        
        config_doc = db.collection("settings").document("financial_settings").get()
        config = config_doc.to_dict() if config_doc.exists else {}
        raw_comm_brackets = config.get("commissionBrackets", [{"maxLimit": 1499, "rate": 25.0}, {"maxLimit": 3999, "rate": 18.0}, {"maxLimit": 999999, "rate": 10.0}])
        comm_brackets = sorted(raw_comm_brackets, key=lambda x: float(x.get("maxLimit", 999999)))
        
        jamba_revenue = 0.0
        orders = db.collection("orders").where("status", "in", ["paid", "processing", "delivered", "settled_override"]).get()
        for doc in orders:
            order = doc.to_dict()
            order_discount = float(order.get("discount_applied", 0))
            promo_role = order.get("promo_creator_role")
            promo_email = order.get("promo_seller_email")
            order_subtotal = float(order.get("subtotal", 0))
            
            for item in order.get("items", []):
                item_price = float(item.get("price", 0))
                item_qty = int(item.get("quantity", 1))
                gross_item_revenue = item_price * item_qty
                seller_email = item.get("sellerEmail", "")
                
                item_discount = 0
                if order_discount > 0:
                    if promo_role == "admin" and order_subtotal > 0:
                        item_discount = order_discount * (gross_item_revenue / order_subtotal)
                    elif promo_role == "seller" and promo_email == seller_email:
                        seller_items = [i for i in order.get("items", []) if i.get("sellerEmail") == seller_email]
                        seller_gross = sum(float(i.get("price", 0)) * int(i.get("quantity", 1)) for i in seller_items)
                        if seller_gross > 0: item_discount = order_discount * (gross_item_revenue / seller_gross)

                discounted_item_revenue = max(gross_item_revenue - item_discount, 0)

                applied_comm_rate = 30.0
                for cb in comm_brackets:
                    if item_price <= float(cb.get("maxLimit", 999999)):
                        applied_comm_rate = float(cb.get("rate", 30.0))
                        break
                        
                jamba_revenue += discounted_item_revenue * (applied_comm_rate / 100.0)

        return jsonify({"jambaRevenue": round(jamba_revenue, 2), "pendingPayouts": round(pending_payouts, 2), "inEscrow": round(in_escrow, 2), "totalGST": round(jamba_revenue * 0.18, 2)}), 200
    except Exception as e:
        logger.error(f"Error fetching finance KPIs: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/transactions", methods=["GET"])
@admin_required
def admin_transactions():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try: return jsonify([{**doc.to_dict(), "id": doc.id} for doc in db.collection("transactions").order_by("created_at", direction=firestore.Query.DESCENDING).limit(int(request.args.get("limit", 100))).get()]), 200
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/finance/adjust", methods=["POST"])
@admin_required
def inject_financial_adjustment():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        data = request.get_json()
        amount = float(data.get("amount", 0))
        db.collection("transactions").add({"txId": f"ADJ-{int(datetime.now(timezone.utc).timestamp())}", "date": datetime.now(timezone.utc).strftime("%d %b %Y"), "created_at": datetime.now(timezone.utc).isoformat(), "type": "Bonus" if amount >= 0 else "Penalty", "brand": data.get("brand", "Global Correction"), "amount": f"+ ₹{amount}" if amount >= 0 else f"- ₹{abs(amount)}", "status": f"Applied: {data.get('reason', 'Force Adj')}"})
        return jsonify({"status": "success"}), 201
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/payouts/<payout_id>", methods=["PUT"])
@admin_required
def update_payout(payout_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        data = request.get_json()
        payout_ref = db.collection("payout_requests").document(v_doc_id(payout_id))
        payout_doc = payout_ref.get()
        if not payout_doc.exists: return jsonify({"error": "Payout not found"}), 404
        update_payload = pick(data, PAYOUT_ADMIN_FIELDS)
        if "status" in update_payload: update_payload["status"] = v_choice(update_payload["status"], {"pending", "approved", "on_hold", "paid", "rejected"}, "status")
        if "utr" in update_payload: update_payload["utr"] = v_str(update_payload["utr"], 40, "UTR")
        update_payload.update({"updated_by": request.admin_email, "updated_at": datetime.now(timezone.utc).isoformat()})
        payout_ref.update(update_payload)
        
        if update_payload.get("status") == "paid":
            pinfo = payout_doc.to_dict()
            db.collection("transactions").add({"txId": f"TXN-{int(datetime.now(timezone.utc).timestamp())}", "date": datetime.now(timezone.utc).strftime("%d %b %Y"), "created_at": datetime.now(timezone.utc).isoformat(), "type": "Payout", "brand": pinfo.get("brand", "Unknown Seller"), "amount": f"- ₹{pinfo.get('amount', pinfo.get('netPayable', 0))}", "status": f"Paid (UTR: {update_payload.get('utr', 'N/A')})", "payout_id": payout_id})
        return jsonify({"status": "Payout updated"}), 200
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

# ==========================================
# 8. SELLER ONBOARDING, FINANCE & ORDERS
# ==========================================
@app.route("/api/v1/seller/onboarding", methods=["GET", "POST"])
def seller_onboarding():
    """Handles checking status (GET) and submitting KYC applications (POST)"""
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    user = _verify_bearer()
    if not user: return jsonify({"error": "Unauthorized"}), 401
    
    email = user.get("email", "").lower()
    uid = user.get("uid", "")
    
    if request.method == "GET":
        seller_doc = db.collection("authorized_sellers").document(email).get()
        if seller_doc.exists:
            return jsonify({
                "status": "approved", 
                "hasSeenCongrats": seller_doc.to_dict().get("hasSeenCongrats", False)
            }), 200
            
        app_doc = db.collection("seller_applications").document(uid).get()
        if not app_doc.exists:
            app_doc = db.collection("seller_applications").document(email).get()
        if not app_doc.exists:
            q = db.collection("seller_applications").where("email", "==", email).limit(1).get()
            if q: app_doc = q[0]
            
        if app_doc and app_doc.exists:
            app_data = app_doc.to_dict()
            return jsonify({"status": app_data.get("status", "kyc_submitted"), "application": app_data}), 200
            
        return jsonify({"status": "none"}), 200
        
    if request.method == "POST":
        data = request.get_json() or {}
        now = datetime.now(timezone.utc).isoformat()
        
        app_doc = db.collection("seller_applications").document(uid).get()
        if not app_doc.exists:
            app_doc = db.collection("seller_applications").document(email).get()
            
        rejection_count = 0
        if app_doc and app_doc.exists:
            app_data = app_doc.to_dict()
            if app_data.get("status") == "blacklisted":
                return jsonify({"error": "Account blacklisted due to multiple rejections."}), 403
            rejection_count = app_data.get("rejectionCount", 0)

        payload = {
            **data, "email": email, "uid": uid,
            "status": data.get("status", "kyc_submitted"),
            "rejectionCount": rejection_count, "updatedAt": now
        }
        if "createdAt" not in payload:
            payload["createdAt"] = now
            
        db.collection("seller_applications").document(uid).set(payload, merge=True)
        return jsonify({"status": "kyc_submitted"}), 201

@app.route("/api/v1/seller/mark_congrats", methods=["POST"])
def mark_congrats_seen():
    """Permanently marks the congratulations screen as seen for this seller."""
    user = _verify_bearer()
    if not user: return jsonify({"error": "Unauthorized"}), 401
    email = user.get("email", "").lower()
    
    if db is not None:
        doc_ref = db.collection("authorized_sellers").document(email)
        if doc_ref.get().exists:
            doc_ref.update({"hasSeenCongrats": True})
            
    return jsonify({"status": "success"}), 200

@app.route("/api/v1/seller/profile", methods=["GET", "PUT"])
@seller_required
def manage_seller_profile():
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    profile_ref = db.collection("seller_profiles").document(request.seller_email)
    
    if request.method == "GET":
        doc = profile_ref.get()
        return jsonify(doc.to_dict() if doc.exists else {}), 200
        
    if request.method == "PUT":
        data = request.get_json()
        data["updated_at"] = datetime.now(timezone.utc).isoformat()
        profile_ref.set(data, merge=True)
        return jsonify({"status": "success"}), 200

@app.route("/api/v1/seller/products", methods=["GET", "POST"])
@seller_required
def manage_seller_products():
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    
    if request.method == "GET":
        products = [{**doc.to_dict(), "id": doc.id} for doc in db.collection("products").where("sellerEmail", "==", request.seller_email).get()]
        return jsonify(products), 200
        
    if request.method == "POST":
        data = request.get_json()
        now = datetime.now(timezone.utc).isoformat()
        data["sellerEmail"] = request.seller_email
        data["created_at"] = now
        
        # 🔥 Generate Initial Audit Event 🔥
        data["audit_history"] = [{
            "action": "created",
            "timestamp": now,
            "actor_role": "seller",
            "actor_id": request.seller_email,
            "details": "Product uploaded to marketplace"
        }]
        
        _, doc_ref = db.collection("products").add(data)
        return jsonify({"status": "success", "id": doc_ref.id}), 201

@app.route("/api/v1/seller/products/<product_id>", methods=["PUT"])
@seller_required
def update_seller_product(product_id):
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    doc_ref = db.collection("products").document(product_id)
    if doc_ref.get().to_dict().get("sellerEmail") != request.seller_email:
        return jsonify({"error": "Forbidden"}), 403
        
    data = request.get_json()
    
    # SECURITY FIX: Prevent sellers from unblocking their own products via the API
    data.pop("approval_status", None)
    data.pop("blocked_reason", None)
    
    # 🔥 Generate Audit Event 🔥
    action = "edited"
    details = "Seller updated product details"
    
    if "isDeleted" in data:
        action = "soft_delete" if data["isDeleted"] else "restore"
        details = f"Seller {'archived' if data['isDeleted'] else 'restored'} the product"
    elif "isHidden" in data:
        action = "edited"
        details = f"Seller made product {'hidden' if data['isHidden'] else 'visible'}"
    elif "isOutOfStock" in data:
        action = "edited"
        details = f"Seller marked product as {'Out of Stock' if data['isOutOfStock'] else 'In Stock'}"

    audit_entry = {
        "action": action,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor_role": "seller",
        "actor_id": request.seller_email,
        "details": details
    }

    update_payload = {**data, "audit_history": firestore.ArrayUnion([audit_entry])}
    doc_ref.update(update_payload)
    return jsonify({"status": "success"}), 200

@app.route("/api/v1/seller/reviews", methods=["GET"])
@seller_required
def get_seller_reviews():
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    try:
        reviews = []
        for doc in db.collection("reviews").where("sellerEmail", "==", request.seller_email).get():
            r = doc.to_dict()
            r["id"] = doc.id
            if "createdAt" in r and hasattr(r["createdAt"], "isoformat"):
                r["createdAt"] = r["createdAt"].isoformat()
            reviews.append(r)
        return jsonify(reviews), 200
    except Exception as e:
        logger.error(f"Error fetching seller reviews: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/v1/seller/reviews/<review_id>/reply", methods=["POST"])
@seller_required
def reply_seller_review(review_id):
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    try:
        data = request.get_json() or {}
        db.collection("reviews").document(v_doc_id(review_id)).update({
            "sellerReply": v_str(data.get("replyText", ""), 1000, "replyText"),
            "repliedAt": datetime.now(timezone.utc).isoformat()
        })
        return jsonify({"status": "success"}), 200
    except Exception as e:
        logger.error(f"Error replying to review: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/v1/seller/tickets", methods=["GET", "POST"])
@seller_required
def manage_seller_tickets():
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    
    if request.method == "GET":
        try:
            own_docs = db.collection("support_tickets").where("sellerEmail", "==", request.seller_email).get()
            broadcast_docs = db.collection("support_tickets").where("sellerEmail", "==", "all").get()
            
            tickets_map = {}
            for doc in list(own_docs) + list(broadcast_docs):
                t = doc.to_dict()
                t["id"] = doc.id
                if "date" in t and hasattr(t["date"], "isoformat"):
                    t["date"] = t["date"].isoformat()
                elif "date" not in t:
                    t["date"] = datetime.now(timezone.utc).isoformat()
                if not isinstance(t.get("messages"), list):
                    t["messages"] = []
                tickets_map[doc.id] = t
                
            tickets = list(tickets_map.values())
            tickets.sort(key=lambda x: str(x.get("date", "")), reverse=True)
            return jsonify(tickets), 200
        except Exception as e:
            logger.error(f"Error fetching seller tickets: {str(e)}", exc_info=True)
            return jsonify({"error": "Internal server error"}), 500
            
    if request.method == "POST":
        try:
            data = request.get_json() or {}
            now = datetime.now(timezone.utc).isoformat()
            
            incoming_messages = data.get("messages", [])
            if isinstance(incoming_messages, list) and len(incoming_messages) > 0 and isinstance(incoming_messages[0], dict):
                message_text = incoming_messages[0].get("text", "")
            else:
                message_text = data.get("message", "")

            new_ticket = {
                "sellerEmail": request.seller_email,
                "email": request.seller_email,
                "sellerName": v_str(data.get("sellerName", request.seller_email), 150, "sellerName"),
                "subject": v_str(data.get("subject", "General Support"), 200, "subject"),
                "status": "open",
                "date": now,
                "messages": [
                    {
                        "sender": "seller",
                        "text": v_str(message_text, 2000, "message"),
                        "time": now
                    }
                ]
            }
            _, doc_ref = db.collection("support_tickets").add(new_ticket)
            return jsonify({"id": doc_ref.id, "status": "success"}), 201
        except Exception as e:
            logger.error(f"Error creating seller ticket: {str(e)}", exc_info=True)
            return jsonify({"error": "Internal server error"}), 500

@app.route("/api/v1/seller/tickets/<ticket_id>/reply", methods=["POST"])
@seller_required
def reply_seller_ticket(ticket_id):
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    try:
        data = request.get_json() or {}
        msg_obj = data.get("message", {})
        msg_text = msg_obj.get("text", "") if isinstance(msg_obj, dict) else str(msg_obj)
        
        reply_entry = {
            "sender": "seller",
            "text": v_str(msg_text, 2000, "message"),
            "time": datetime.now(timezone.utc).isoformat()
        }
        
        db.collection("support_tickets").document(v_doc_id(ticket_id)).update({
            "messages": firestore.ArrayUnion([reply_entry]),
            "status": "open"
        })
        return jsonify({"status": "success"}), 200
    except Exception as e:
        logger.error(f"Error replying to ticket {ticket_id}: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/v1/seller/orders", methods=["GET"])
@seller_required
def get_seller_orders():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        current_seller_email = request.seller_email
        orders_query = db.collection("orders").where("sellerEmails", "array_contains", current_seller_email).get()
        
        seller_orders = []
        for doc in orders_query:
            order_data = doc.to_dict()
            order_data["id"] = doc.id
            
            isolated_items = [item for item in order_data.get("items", []) if (item.get("sellerEmail") or "").lower() == current_seller_email.lower()]
            order_data["items"] = isolated_items
            order_data["sellerSubtotal"] = sum(float(item.get("price", 0)) * int(item.get("quantity", 1)) for item in isolated_items)
            
            order_data.pop("total", None)
            order_data.pop("subtotal", None)
            order_data.pop("total_gst", None)
            
            seller_orders.append(order_data)
            
        seller_orders.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return jsonify(seller_orders), 200
    except Exception as e:
        logger.error(f"Error fetching orders: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/v1/seller/orders/<order_id>/accept", methods=["POST"])
@seller_required
def accept_seller_order(order_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        order_ref = db.collection("orders").document(v_doc_id(order_id))
        order_doc = order_ref.get()
        if not order_doc.exists or request.seller_email not in order_doc.to_dict().get("sellerEmails", []):
            return jsonify({"error": "Order not found or unauthorized"}), 404
            
        order_ref.update({"seller_accepted": True, "accepted_at": datetime.now(timezone.utc).isoformat()})
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/v1/seller/dashboard", methods=["GET"])
@seller_required
def get_isolated_seller_data():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        current_seller_email = request.seller_email 
        
        config_doc = db.collection("settings").document("financial_settings").get()
        config = config_doc.to_dict() if config_doc.exists else {}
        
        raw_comm_brackets = config.get("commissionBrackets", [
            {"maxLimit": 1499, "rate": 25.0}, 
            {"maxLimit": 3999, "rate": 18.0}, 
            {"maxLimit": 999999, "rate": 10.0}
        ])
        comm_brackets = sorted(raw_comm_brackets, key=lambda x: float(x.get("maxLimit", 999999)))
        
        tcs_percent = float(config.get("tcsRate", 1.0))
        raw_brackets = config.get("gstBrackets", [{"maxLimit": 2500, "rate": 5.0}, {"maxLimit": 999999, "rate": 18.0}])
        gst_brackets = sorted(raw_brackets, key=lambda x: float(x.get("maxLimit", 999999)))
        
        seller_doc = db.collection("authorized_sellers").document(current_seller_email).get()
        has_gst = seller_doc.to_dict().get("kycData", {}).get("hasGst", False) if seller_doc.exists else False

        orders_query = db.collection("orders").where("sellerEmails", "array_contains", current_seller_email).get()
        secure_wallet = {"available": 0, "pending": 0, "lifetime": 0}
        isolated_sales_ledger = []
        
        for doc in orders_query:
            order = doc.to_dict()
            order_status = order.get("status", "pending")
            
            if order_status == "rto_delivered":
                rto_penalty = 150.0
                isolated_sales_ledger.append({
                    "order_id": order.get("jamba_order_id", "N/A"), "date": order.get("updated_at", order.get("created_at")), "product_name": "RTO Logistics Penalty",
                    "qty": 0, "gross": 0, "fee": 0, "commission_gst": 0,
                    "tcs": 0, "net": -rto_penalty, "status": "rto_delivered"
                })
                secure_wallet["available"] -= rto_penalty
                secure_wallet["lifetime"] -= rto_penalty
                continue

            if order_status not in ["paid", "processing", "shipped", "out_for_delivery", "delivered", "settled_override", "rto_initiated", "return_requested", "returned"]: continue
                
            order_discount = float(order.get("discount_applied", 0))
            promo_role = order.get("promo_creator_role")
            promo_email = order.get("promo_seller_email")
            seller_bears_discount = (promo_role == "seller" and promo_email == current_seller_email)
            
            seller_items = [i for i in order.get("items", []) if (i.get("sellerEmail") or "").lower() == current_seller_email.lower()]
            seller_gross_total = sum(float(i.get("price", 0)) * int(i.get("quantity", 1)) for i in seller_items)
                
            for item in seller_items:
                item_price = float(item.get("price", 0))
                item_qty = int(item.get("quantity", 1))
                gross_item_revenue = item_price * item_qty
                
                item_discount = 0
                if seller_bears_discount and seller_gross_total > 0:
                    item_discount = order_discount * (gross_item_revenue / seller_gross_total)
                    
                discounted_item_revenue = max(gross_item_revenue - item_discount, 0)
                
                applied_comm_rate = 30.0
                for cb in comm_brackets:
                    if item_price <= float(cb.get("maxLimit", 999999)):
                        applied_comm_rate = float(cb.get("rate", 30.0))
                        break

                jamba_fee = discounted_item_revenue * (applied_comm_rate / 100.0)
                commission_gst = jamba_fee * 0.18
                
                product_gst_percent = 18.0
                for bracket in gst_brackets:
                    if item_price <= float(bracket.get("maxLimit", 999999)):
                        product_gst_percent = float(bracket.get("rate", 18.0))
                        break
                    
                net_product_value = discounted_item_revenue / (1 + (product_gst_percent / 100.0))
                tcs_amount = (net_product_value * (tcs_percent / 100.0)) if has_gst else 0.0
                
                net_seller_earnings = discounted_item_revenue - jamba_fee - commission_gst - tcs_amount
                
                isolated_sales_ledger.append({
                    "order_id": order.get("jamba_order_id", "N/A"), "date": order.get("created_at"), "product_name": item.get("name", item.get("title", "Product")),
                    "qty": item_qty, "gross": round(discounted_item_revenue, 2), "fee": round(jamba_fee, 2), "commission_gst": round(commission_gst, 2),
                    "tcs": round(tcs_amount, 2), "net": round(net_seller_earnings, 2), "status": order_status
                })

                if order_status in ["returned", "return_requested"]:
                    pass
                elif order_status in ["delivered", "settled_override"]:
                    policy = item.get("return_policy", "7_day_return_replace")
                    hold_days = 3 if policy == "final_sale" else 9
                    delivered_at = order.get("delivered_at") or order.get("created_at") or ""
                    try:
                        delivered_ts = datetime.fromisoformat(str(delivered_at).replace("Z", "+00:00")).timestamp()
                        if datetime.now(timezone.utc).timestamp() - (hold_days * 86400) > delivered_ts or order_status == "settled_override":
                            secure_wallet["available"] += net_seller_earnings
                        else:
                            secure_wallet["pending"] += net_seller_earnings
                    except ValueError:
                        secure_wallet["pending"] += net_seller_earnings
                    secure_wallet["lifetime"] += net_seller_earnings
                elif order_status in ["paid", "processing", "shipped", "out_for_delivery", "rto_initiated"]:
                    secure_wallet["pending"] += net_seller_earnings
                    secure_wallet["lifetime"] += net_seller_earnings

        for doc in db.collection("payout_requests").where("email", "==", current_seller_email).get():
            amt = float(doc.to_dict().get("amount", 0))
            if doc.to_dict().get("status") in ["paid", "pending"]: secure_wallet["available"] -= amt
            
        if secure_wallet["available"] < 0: secure_wallet["available"] = 0
        isolated_sales_ledger.sort(key=lambda x: x.get("date", ""), reverse=True)

        return jsonify({
            "hasGst": has_gst,
            "wallet": {"available": round(secure_wallet["available"], 2), "pending": round(secure_wallet["pending"], 2), "lifetime": round(secure_wallet["lifetime"], 2)},
            "sales_ledger": isolated_sales_ledger
        }), 200
    except Exception as e: 
        logger.error(f"Pipeline error for seller {request.seller_email}: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to route financial data"}), 500

@app.route("/api/v1/seller/payouts/history", methods=["GET"])
@seller_required
def get_payout_history():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        history = [{**doc.to_dict(), "id": doc.id} for doc in db.collection("payout_requests").where("email", "==", request.seller_email).get()]
        history.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return jsonify(history), 200
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

def compute_available_balance(seller_email):
    """Server-side source of truth for what a seller can withdraw."""
    cfg_doc = db.collection("settings").document("financial_settings").get()
    cfg = cfg_doc.to_dict() if cfg_doc.exists else {}
    
    raw_comm_brackets = cfg.get("commissionBrackets", [{"maxLimit": 1499, "rate": 25.0}, {"maxLimit": 3999, "rate": 18.0}, {"maxLimit": 999999, "rate": 10.0}])
    comm_brackets = sorted(raw_comm_brackets, key=lambda x: float(x.get("maxLimit", 999999)))
    
    tcs_percent = float(cfg.get("tcsRate", 1.0))
    raw_gst_brackets = cfg.get("gstBrackets", [{"maxLimit": 2500, "rate": 5.0}, {"maxLimit": 999999, "rate": 18.0}])
    gst_brackets = sorted(raw_gst_brackets, key=lambda x: float(x.get("maxLimit", 999999)))
    
    seller_doc = db.collection("authorized_sellers").document(seller_email).get()
    has_gst = seller_doc.to_dict().get("kycData", {}).get("hasGst", False) if seller_doc.exists else False

    earned = 0.0
    for o in db.collection("orders").where("sellerEmails", "array_contains", seller_email).get():
        od = o.to_dict()
        status = od.get("status")
        
        if status == "rto_delivered":
            earned -= 150.0  
            continue

        if status not in ["delivered", "settled_override"]: continue
        
        delivered_at = od.get("delivered_at") or od.get("created_at") or ""
        try:
            delivered_ts = datetime.fromisoformat(str(delivered_at).replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
            
        order_discount = float(od.get("discount_applied", 0))
        promo_role = od.get("promo_creator_role")
        promo_email = od.get("promo_seller_email")
        seller_bears_discount = (promo_role == "seller" and promo_email == seller_email)
        
        seller_items = [i for i in od.get("items", []) if (i.get("sellerEmail") or "").lower() == seller_email.lower()]
        seller_gross_total = sum(float(i.get("price", 0)) * int(i.get("quantity", 1)) for i in seller_items)

        for it in seller_items:
            policy = it.get("return_policy", "7_day_return_replace")
            hold_days = 3 if policy == "final_sale" else 9
            cutoff = datetime.now(timezone.utc).timestamp() - hold_days * 86400
            
            if delivered_ts > cutoff and status != "settled_override":
                continue 

            item_price = float(it.get("price", 0))
            item_qty = int(it.get("quantity", 1))
            gross_item_revenue = item_price * item_qty
            
            item_discount = order_discount * (gross_item_revenue / seller_gross_total) if (seller_bears_discount and seller_gross_total > 0) else 0
            discounted_item_revenue = max(gross_item_revenue - item_discount, 0)
            
            applied_comm_rate = 30.0
            for cb in comm_brackets:
                if item_price <= float(cb.get("maxLimit", 999999)):
                    applied_comm_rate = float(cb.get("rate", 30.0))
                    break
                    
            jamba_fee = discounted_item_revenue * (applied_comm_rate / 100.0)
            commission_gst = jamba_fee * 0.18
            
            product_gst_percent = 18.0
            for bracket in gst_brackets:
                if item_price <= float(bracket.get("maxLimit", 999999)):
                    product_gst_percent = float(bracket.get("rate", 18.0))
                    break
            
            net_product_value = discounted_item_revenue / (1 + (product_gst_percent / 100.0))
            tcs_deduction = (net_product_value * (tcs_percent / 100.0)) if has_gst else 0.0
            
            earned += discounted_item_revenue - jamba_fee - commission_gst - tcs_deduction
            
    withdrawn = sum([float(pd.to_dict().get("amount", 0)) for pd in db.collection("payout_requests").where("email", "==", seller_email).get() if pd.to_dict().get("status") in ("pending", "approved", "paid", "on_hold")])
    return round(max(earned - withdrawn, 0), 2)

@app.route("/api/v1/seller/payouts/request", methods=["POST"])
@seller_required
def request_payout():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    
    idempotency_key = request.headers.get("Idempotency-Key")
    if idempotency_key:
        existing_req = db.collection("idempotency_logs").document(idempotency_key).get()
        if existing_req.exists:
            return jsonify(existing_req.to_dict().get("response")), 201

    try:
        data = request.get_json()
        amount = v_float(data.get("amount", 0), 1, 10_000_000, "amount")
        if amount > compute_available_balance(request.seller_email): 
            return jsonify({"error": "Amount exceeds available balance"}), 400

        transaction = db.transaction()
        pending_query = db.collection("payout_requests").where("email", "==", request.seller_email).where("status", "==", "pending").limit(1)

        @firestore.transactional
        def process_payout_safely(transaction, query):
            existing = list(query.stream(transaction=transaction))
            if len(existing) > 0:
                raise ValueError("You already have a pending payout request")
                
            new_ref = db.collection("payout_requests").document()
            transaction.set(new_ref, {
                "email": request.seller_email, "brand": v_str(data.get("brand", "Unknown Brand"), 100, "brand"),
                "amount": amount, "netPayable": amount, "status": "pending",
                "created_at": datetime.now(timezone.utc).isoformat(), "utr": ""
            })
            return new_ref.id

        new_id = process_payout_safely(transaction, pending_query)
        response_payload = {"status": "success", "id": new_id}
        
        if idempotency_key:
            db.collection("idempotency_logs").document(idempotency_key).set({
                "response": response_payload, "created_at": datetime.now(timezone.utc).isoformat()
            })
            
        return jsonify(response_payload), 201
    except ValueError as ve: return jsonify({"error": str(ve)}), 400
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

# ==========================================
# 9. PROMO CODE ENGINE & CHECKOUT VALIDATION
# ==========================================
@app.route("/admin/promocodes", methods=["GET", "POST"])
@admin_required
def admin_promocodes():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        if request.method == "GET":
            return jsonify([{**doc.to_dict(), "id": doc.id} for doc in db.collection("promocodes").order_by("created_at", direction=firestore.Query.DESCENDING).get()]), 200
        if request.method == "POST":
            data = request.get_json()
            code = data.get("code", "").strip().upper()
            if len(db.collection("promocodes").where("code", "==", code).get()) > 0: return jsonify({"error": f"Promo code {code} already exists!"}), 400
            _, doc_ref = db.collection("promocodes").add({"code": code, "type": data.get("type", "percentage"), "value": float(data.get("value", 0)), "creator_role": "admin", "seller_email": None, "status": "active", "usage_limit": data.get("usage_limit", "unlimited"), "applicable_payment_method": data.get("payment_method", "all"), "valid_from": data.get("valid_from"), "valid_until": data.get("valid_until"), "used_by": [], "created_at": datetime.now(timezone.utc).isoformat()})
            return jsonify({"status": "success", "id": doc_ref.id}), 201
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/promocodes/<doc_id>", methods=["PUT", "DELETE"])
@admin_required
def manage_promocode(doc_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        doc_ref = db.collection("promocodes").document(doc_id)
        if request.method == "PUT":
            doc_ref.update({"status": request.get_json().get("status", "pending")})
            return jsonify({"status": "success"}), 200
        if request.method == "DELETE":
            doc_ref.delete()
            return jsonify({"status": "success"}), 200
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

@app.route("/api/v1/seller/promocodes", methods=["GET", "POST"])
@seller_required
def seller_promocodes():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        if request.method == "GET":
            promos = [{**doc.to_dict(), "id": doc.id} for doc in db.collection("promocodes").where("seller_email", "==", request.seller_email).get()]
            promos.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            return jsonify(promos), 200
        if request.method == "POST":
            data = request.get_json()
            code = str(data.get("code", "")).strip().upper()
            if not PROMO_RE.match(code): return jsonify({"error": "Code must be 3-24 letters/numbers"}), 400
            if len(db.collection("promocodes").where("code", "==", code).get()) > 0: return jsonify({"error": f"Promo code {code} is already taken!"}), 400
            _, doc_ref = db.collection("promocodes").add({"code": code, "type": v_choice(data.get("type", "percentage"), {"percentage", "flat"}, "type"), "value": v_float(data.get("value", 0), 1, 90 if data.get("type", "percentage") == "percentage" else 100000, "value"), "creator_role": "seller", "seller_email": request.seller_email, "status": "pending", "usage_limit": v_choice(data.get("usage_limit", "unlimited"), {"single", "unlimited"}, "usage limit"), "applicable_payment_method": v_choice(data.get("payment_method", "all"), {"all", "online", "cod"}, "payment method"), "valid_from": v_str(data.get("valid_from"), 40, "valid_from") or None, "valid_until": v_str(data.get("valid_until"), 40, "valid_until") or None, "used_by": [], "created_at": datetime.now(timezone.utc).isoformat()})
            return jsonify({"status": "success", "id": doc_ref.id}), 201
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

@app.route("/api/v1/promocodes/validate", methods=["POST"])
@limiter.limit("10 per minute")
def validate_promocode():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        data = request.get_json()
        code = str(data.get("code", "")).strip().upper()
        if not PROMO_RE.match(code): return jsonify({"error": "Invalid promo code"}), 404
        user = optional_user()
        customer_email = user["email"].lower() if user else str(data.get("email", "")).strip().lower()

        query = db.collection("promocodes").where("code", "==", code).limit(1).get()
        if not query: return jsonify({"error": "Invalid promo code"}), 404
        promo = query[0].to_dict()
        if promo.get("status") != "active": return jsonify({"error": "Promo code is not active or awaiting approval"}), 400
        now = datetime.now(timezone.utc).isoformat()
        
        if promo.get("valid_from"):
            promo_start = promo.get("valid_from")
            if not promo_start.endswith("Z") and "+" not in promo_start: promo_start += "+05:30" 
            if now < promo_start: return jsonify({"error": "Promo code is not yet valid"}), 400
                
        if promo.get("valid_until"):
            promo_end = promo.get("valid_until")
            if not promo_end.endswith("Z") and "+" not in promo_end: promo_end += "+05:30"
            if now > promo_end: return jsonify({"error": "Promo code has expired"}), 400

        if promo.get("usage_limit") == "single" and customer_email and customer_email in promo.get("used_by", []):
            return jsonify({"error": "You have already used this promo code"}), 400

        return jsonify({"status": "success", "type": promo.get("type"), "value": promo.get("value"), "creator_role": promo.get("creator_role"), "seller_brand": promo.get("seller_brand", "")}), 200
    except Exception as e: return jsonify({"error": "Internal server error"}), 500

# ==========================================
# 10. CUSTOMER DASHBOARD & ACCOUNT APIS
# ==========================================
@app.route("/api/v1/customer/orders", methods=["GET"])
def get_customer_orders():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    
    user = _verify_bearer()
    if not user: return jsonify({"error": "Unauthorized"}), 401
    
    try:
        user_email = user.get("email", "").lower()
        user_uid = user.get("uid", "")
        
        orders_by_uid = db.collection("orders").where("userId", "==", user_uid).get()
        orders_by_email = db.collection("orders").where("email", "==", user_email).get()
        
        orders_map = {}
        for doc in list(orders_by_uid) + list(orders_by_email):
            data = doc.to_dict()
            data["id"] = doc.id
            orders_map[doc.id] = data
            
        customer_orders = list(orders_map.values())
        customer_orders.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        
        return jsonify(customer_orders), 200
    except Exception as e:
        logger.error(f"Error fetching customer orders: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/v1/customer/reviews", methods=["GET", "POST"])
def manage_customer_reviews():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    user = _verify_bearer()
    if not user: return jsonify({"error": "Unauthorized"}), 401
    
    uid = user.get("uid", "")
    
    if request.method == "GET":
        try:
            docs = db.collection("reviews").where("userId", "==", uid).get()
            reviews = []
            for d in docs:
                r = d.to_dict()
                r["id"] = d.id
                if "createdAt" in r and hasattr(r["createdAt"], "isoformat"):
                    r["createdAt"] = r["createdAt"].isoformat()
                reviews.append(r)
            return jsonify(reviews), 200
        except Exception as e:
            logger.error(f"Error fetching customer reviews: {str(e)}")
            return jsonify({"error": "Internal server error"}), 500
            
    if request.method == "POST":
        try:
            data = request.get_json() or {}
            review_doc = {
                "productId": v_doc_id(data.get("productId"), "productId"),
                "orderId": v_doc_id(data.get("orderId"), "orderId") if data.get("orderId") else "",
                "sellerEmail": v_str(data.get("sellerEmail", ""), 190, "sellerEmail"),
                "brandName": v_str(data.get("brandName", "JAMBAWEAR"), 100, "brandName"),
                "sellerId": v_str(data.get("sellerId", "JAMBA_DIRECT"), 100, "sellerId"),
                "userId": uid,
                "userName": v_str(user.get("name") or data.get("userName") or "Jamba Customer", 100, "userName"),
                "rating": v_int(data.get("rating", 5), 1, 5, "rating"),
                "reviewText": v_str(data.get("reviewText", ""), 2000, "reviewText"),
                "images": [v_str(url, 500, "image_url") for url in (data.get("images") or [])[:5]],
                "createdAt": datetime.now(timezone.utc).isoformat()
            }
            _, doc_ref = db.collection("reviews").add(review_doc)
            return jsonify({"status": "success", "id": doc_ref.id}), 201
        except BadInput as be:
            return jsonify({"error": str(be)}), 400
        except Exception as e:
            logger.error(f"Error submitting customer review: {str(e)}")
            return jsonify({"error": "Internal server error"}), 500

@app.route("/api/v1/public/config/<doc_id>", methods=["GET"])
@limiter.limit("60 per minute")
def get_public_config(doc_id):
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    doc_snap = db.collection("settings").document(v_doc_id(doc_id, "doc_id")).get()
    return jsonify(doc_snap.to_dict() if doc_snap.exists else {}), 200

@app.route("/api/v1/public/products", methods=["GET"])
@limiter.limit("100 per minute")
def get_all_public_products():
    cache_key = "global:products:public_catalog"
    try:
        if redis_client:
            cached_data = redis_client.get(cache_key)
            if cached_data:
                return jsonify(json.loads(cached_data)), 200
        
        if db is None: return jsonify({"error": "DB unavailable"}), 503
        docs = db.collection("products").get()
        
        products = []
        for doc in docs:
            data = doc.to_dict()
            if not data.get("isHidden", False):
                data["id"] = doc.id
                products.append(data)
        
        if redis_client:
            redis_client.setex(cache_key, 3600, json.dumps(products))
            
        return jsonify(products), 200
    except Exception as e:
        logger.error(f"Error fetching catalog: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/v1/public/products/<item_id>", methods=["GET"])
@limiter.limit("100 per minute")
def get_public_product(item_id):
    clean_id = v_doc_id(item_id, "item_id")
    cache_key = f"global:products:detail:{clean_id}"
    
    try:
        if redis_client:
            cached_data = redis_client.get(cache_key)
            if cached_data:
                return jsonify(json.loads(cached_data)), 200
        
        if db is None: return jsonify({"error": "DB unavailable"}), 503
        
        q = db.collection("products").where("item_id", "==", clean_id).limit(1).get()
        if q:
            data = q[0].to_dict()
            data["id"] = q[0].id
        else:
            doc_snap = db.collection("products").document(clean_id).get()
            if not doc_snap.exists: return jsonify({"error": "Not found"}), 404
            data = doc_snap.to_dict()
            data["id"] = doc_snap.id
            
        if redis_client:
            redis_client.setex(cache_key, 3600, json.dumps(data))
            
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Error fetching product {clean_id}: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/v1/public/recommendations/<category>", methods=["GET"])
def get_recommendations(category):
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    q = db.collection("products").where("category", "==", v_str(category, 100, "category")).limit(10).get()
    return jsonify([{**d.to_dict(), "id": d.id} for d in q if not d.to_dict().get("isHidden")]), 200

@app.route("/api/v1/public/reviews/<product_id>", methods=["GET"])
def get_public_reviews(product_id):
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    q = db.collection("reviews").where("productId", "==", v_doc_id(product_id, "product_id")).get()
    return jsonify([{**d.to_dict(), "id": d.id} for d in q]), 200

@app.route("/api/v1/customer/profile", methods=["GET", "POST"])
def manage_customer_profile():
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    user = _verify_bearer()
    if not user: return jsonify({"error": "Unauthorized"}), 401
    
    doc_ref = db.collection("users").document(user["uid"])
    if request.method == "GET":
        doc_snap = doc_ref.get()
        if doc_snap.exists and (doc_snap.to_dict().get("name") or doc_snap.to_dict().get("ownerName")):
            return jsonify({"exists": True, "profile": doc_snap.to_dict()}), 200
        return jsonify({"exists": False}), 200
        
    data = request.get_json()
    payload = {
        "name": v_str(data.get("name", user.get("name", "JAMBA Member")), 100, "name"),
        "ownerName": v_str(data.get("name", user.get("name", "JAMBA Member")), 100, "name"),
        "email": user.get("email", ""),
        "role": "customer",
        "uid": user["uid"],
        "createdAt": data.get("createdAt", datetime.now(timezone.utc).isoformat())
    }
    if data.get("phone"): payload["phone"] = v_str(data["phone"], 20, "phone")
    doc_ref.set(payload, merge=True)
    return jsonify({"status": "success"}), 200

@app.route("/api/v1/customer/wishlist", methods=["GET", "POST", "DELETE"])
def manage_wishlist():
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    user = _verify_bearer()
    if not user: return jsonify({"error": "Unauthorized"}), 401
    
    if request.method == "GET":
        q = db.collection("users").document(user["uid"]).collection("wishlist").get()
        items = []
        for doc_snap in q:
            pid = doc_snap.to_dict().get("productId")
            p_snap = db.collection("products").document(pid).get()
            if p_snap.exists: items.append({**p_snap.to_dict(), "id": p_snap.id})
        return jsonify(items), 200
        
    data = request.get_json()
    product_id = v_doc_id(data.get("productId"), "product_id")
    wishlist_ref = db.collection("users").document(user["uid"]).collection("wishlist").document(product_id)
    
    if request.method == "POST":
        wishlist_ref.set({"productId": product_id, "addedAt": datetime.now(timezone.utc).isoformat()})
        return jsonify({"status": "success"}), 200
        
    if request.method == "DELETE":
        wishlist_ref.delete()
        return jsonify({"status": "success"}), 200
        
@app.route("/api/v1/customer/wishlist/check/<product_id>", methods=["GET"])
def check_wishlist(product_id):
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    user = _verify_bearer()
    if not user: return jsonify({"inWishlist": False}), 200
    snap = db.collection("users").document(user["uid"]).collection("wishlist").document(v_doc_id(product_id, "product_id")).get()
    return jsonify({"inWishlist": snap.exists}), 200

@app.route("/api/v1/customer/cart", methods=["GET", "POST"])
def manage_cart():
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    user = _verify_bearer()
    if not user: return jsonify({"error": "Unauthorized"}), 401
    cart_ref = db.collection("carts").document(user["uid"])
    
    if request.method == "GET":
        snap = cart_ref.get()
        return jsonify(snap.to_dict().get("items", []) if snap.exists else []), 200
        
    data = request.get_json()
    cart_ref.set({"items": data.get("items", [])}, merge=True)
    return jsonify({"status": "success"}), 200

@app.route("/api/v1/customer/addresses", methods=["GET", "POST"])
def manage_addresses():
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    user = _verify_bearer()
    if not user: return jsonify({"error": "Unauthorized"}), 401
    user_ref = db.collection("users").document(user["uid"])
    
    if request.method == "GET":
        snap = user_ref.get()
        return jsonify(snap.to_dict().get("addresses", []) if snap.exists else []), 200
        
    data = request.get_json()
    if request.method == "POST":
        user_ref.set({"addresses": data.get("addresses", [])}, merge=True)
        return jsonify({"status": "success"}), 200

# ==========================================
# MASTER CONTROL API ROUTES
# ==========================================
@app.route("/api/v1/admin/users", methods=["GET", "POST"])
@admin_required
def master_admin_users():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    if request.admin_email != ALLOWED_ADMIN_EMAIL:
        return jsonify({"error": "Forbidden"}), 403
        
    if request.method == "GET":
        users = [{**doc.to_dict(), "id": doc.id} for doc in db.collection("admin_users").get()]
        return jsonify(users), 200
        
    if request.method == "POST":
        data = request.get_json()
        email = v_email(data.get("email"))
        db.collection("admin_users").document(email).set({
            "email": email,
            "firstName": "Pending",
            "lastName": "Registration...",
            "isAuthorized": True,
            "isOnline": False,
            "forceLogout": False,
            "accessStartTime": "00:00",
            "accessEndTime": "23:59",
            "maxDuration": 60,
            "createdAt": datetime.now(timezone.utc).isoformat()
        })
        return jsonify({"status": "success"}), 201

@app.route("/api/v1/admin/users/<admin_id>", methods=["PUT", "DELETE"])
@admin_required
def master_admin_user_detail(admin_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    if request.admin_email != ALLOWED_ADMIN_EMAIL:
        return jsonify({"error": "Forbidden"}), 403
        
    admin_ref = db.collection("admin_users").document(v_email(admin_id))
    if request.method == "PUT":
        data = request.get_json()
        admin_ref.set(data, merge=True)
        return jsonify({"status": "success"}), 200
        
    if request.method == "DELETE":
        admin_ref.delete()
        return jsonify({"status": "success"}), 200

@app.route("/api/v1/admin/logs", methods=["GET"])
@admin_required
def master_admin_logs():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    if request.admin_email != ALLOWED_ADMIN_EMAIL:
        return jsonify({"error": "Forbidden"}), 403
        
    email = request.args.get("email")
    q = db.collection("admin_audit_logs").order_by("timestamp", direction=firestore.Query.DESCENDING).limit(200)
    if email:
        q = q.where("email", "==", v_email(email))
        
    logs = [{**doc.to_dict(), "id": doc.id} for doc in q.get()]
    return jsonify(logs), 200

# ==========================================
# ADMIN SUB-COMPONENT APIs
# ==========================================
@app.route("/api/v1/admin/subscriptions", methods=["GET"])
@admin_required
def admin_get_subscriptions():
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    users = db.collection("users").where("role", "==", "seller").get()
    return jsonify([{ "id": d.id, **d.to_dict() } for d in users]), 200

@app.route("/api/v1/admin/subscriptions/<user_id>", methods=["PUT"])
@admin_required
def admin_update_subscription(user_id):
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    db.collection("users").document(user_id).update(request.get_json())
    return jsonify({"status": "success"}), 200

@app.route("/api/v1/admin/tickets", methods=["GET", "POST"])
@admin_required
def admin_tickets():
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    if request.method == "GET":
        docs = db.collection("support_tickets").order_by("date", direction=firestore.Query.DESCENDING).get()
        return jsonify([{ "id": d.id, **d.to_dict() } for d in docs]), 200
    if request.method == "POST":
        _, doc_ref = db.collection("support_tickets").add(request.get_json())
        return jsonify({"id": doc_ref.id}), 201

@app.route("/api/v1/admin/tickets/<ticket_id>", methods=["PUT"])
@admin_required
def admin_update_ticket(ticket_id):
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    db.collection("support_tickets").document(ticket_id).update(request.get_json())
    return jsonify({"status": "success"}), 200

@app.route("/api/v1/admin/reviews", methods=["GET"])
@admin_required
def admin_get_reviews():
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    docs = db.collection("reviews").get()
    return jsonify([{ "id": d.id, **d.to_dict() } for d in docs]), 200

@app.route("/api/v1/admin/reviews/<review_id>", methods=["DELETE"])
@admin_required
def admin_delete_review(review_id):
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    db.collection("reviews").document(review_id).delete()
    return jsonify({"status": "success"}), 200

@app.route("/api/v1/admin/seller_applications", methods=["GET"])
@admin_required
def admin_get_applications():
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    docs = db.collection("seller_applications").where("status", "in", ["kyc_submitted", "pending_kyc"]).get()
    return jsonify([{ "id": d.id, **d.to_dict() } for d in docs]), 200

@app.route("/api/v1/admin/seller_applications/<app_id>/<action>", methods=["POST"])
@admin_required
def admin_process_application(app_id, action):
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    app_ref = db.collection("seller_applications").document(app_id)
    
    if action == "approve":
        app_data = app_ref.get().to_dict()
        db.collection("authorized_sellers").document(app_data["email"]).set({
            "email": app_data["email"], "brandName": app_data.get("brandName", ""),
            "ownerName": app_data.get("ownerName", ""), "phone": app_data.get("phone", ""),
            "approvedAt": datetime.now(timezone.utc).isoformat(), "kycData": app_data.get("kycData", {})
        })
        app_ref.update({"status": "approved", "approvedAt": datetime.now(timezone.utc).isoformat(), "reviewedBy": request.admin_email})
        
    elif action == "reject":
        app_data = app_ref.get().to_dict()
        new_rejection_count = app_data.get("rejectionCount", 0) + 1
        
        # 5 Strikes and you're blacklisted logic
        new_status = "blacklisted" if new_rejection_count >= 5 else "rejected"
        
        app_ref.update({
            "status": new_status,
            "rejectionCount": new_rejection_count,
            "rejectedAt": datetime.now(timezone.utc).isoformat(),
            "reviewedBy": request.admin_email,
            "rejectionReason": request.get_json().get("reason", "")
        })
    return jsonify({"status": "success"}), 200

@app.route("/api/v1/admin/categories", methods=["GET", "POST"])
@admin_required
def admin_categories():
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    if request.method == "GET":
        docs = db.collection("categories").get()
        return jsonify([{ "id": d.id, **d.to_dict() } for d in docs]), 200
    if request.method == "POST":
        data = request.get_json()
        db.collection("categories").document(data["slug"]).set({"name": data["name"], "subcategories": data.get("subcategories", [])})
        return jsonify({"status": "success"}), 201

@app.route("/api/v1/admin/categories/<cat_id>", methods=["PUT", "DELETE"])
@admin_required
def admin_category_detail(cat_id):
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    cat_ref = db.collection("categories").document(cat_id)
    if request.method == "PUT":
        cat_ref.update(request.get_json())
        return jsonify({"status": "success"}), 200
    if request.method == "DELETE":
        cat_ref.delete()
        return jsonify({"status": "success"}), 200

@app.route("/api/v1/admin/seller_profiles", methods=["GET"])
@admin_required
def admin_get_all_seller_profiles():
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    docs = db.collection("seller_profiles").get()
    return jsonify([{ "id": d.id, **d.to_dict() } for d in docs]), 200
    
@app.route("/api/v1/admin/seller_profiles/<email>/suspend", methods=["PUT"])
@admin_required
def admin_suspend_store(email):
    if db is None: return jsonify({"error": "DB unavailable"}), 503
    suspend_status = request.get_json().get("isSuspended", True)
    db.collection("seller_profiles").document(v_email(email)).update({"storefront.isSuspended": suspend_status})
    return jsonify({"status": "success"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)