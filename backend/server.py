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
# Industry Standard: Configure robust logging instead of print()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("jambawear_api")

app = Flask(__name__)

# Industry Standard: Restrict CORS in production
# Update this to your actual Vercel/Netlify React URL before going live
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
CORS(app, resources={r"/*": {"origins": ALLOWED_ORIGINS}})

# Admin Email from your React Code
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
# 4. SECURITY MIDDLEWARE
# ==========================================
def admin_required(f):
    """
    Validates the Firebase Auth Token sent by the React frontend.
    Ensures only the true admin can access these routes.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            logger.warning("Unauthorized access attempt: Missing or invalid token.")
            return jsonify({"error": "Unauthorized: Missing token"}), 401
        
        token = auth_header.split(" ")[1]
        try:
            # Verify the token with Firebase
            decoded_token = firebase_auth.verify_id_token(token)
            
            # Verify it belongs to the admin
            if decoded_token.get("email") != ALLOWED_ADMIN_EMAIL:
                logger.warning(f"Forbidden access attempt by: {decoded_token.get('email')}")
                return jsonify({"error": "Forbidden: Insufficient permissions"}), 403
                
        except Exception as e:
            logger.error(f"Token verification failed: {str(e)}")
            return jsonify({"error": "Unauthorized: Invalid or expired token"}), 401
            
        return f(*args, **kwargs)
    return decorated_function

# ==========================================
# 5. PUBLIC ROUTES (Customer Facing)
# ==========================================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "server": "running",
        "firebase_connected": db is not None,
        "razorpay_configured": RAZORPAY_KEY_SECRET != "YOUR_SECRET_KEY_HERE",
        "timestamp": datetime.utcnow().isoformat()
    }), 200

@app.route("/create-order", methods=["POST"])
def create_order():
    if db is None: return jsonify({"error": "Database unavailable"}), 503

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON payload"}), 400

        cart = data.get("cart", [])
        customer_email = data.get("customer", "guest@jambawear.com")
        shipping_address = data.get("shippingAddress") or data.get("shipping_address", {})
        payment_method = data.get("payment_method", "Razorpay")

        secure_subtotal = 0
        enriched_cart = []

        # Validate pricing against the database (Trust Server, Not Client)
        for item in cart:
            item_id = str(item.get("id"))
            quantity = int(item.get("quantity", 1))
            
            doc_ref = db.collection("products").document(item_id).get()
            if not doc_ref.exists:
                # Fallback to query if item_id isn't the document ID
                query = db.collection("products").where("item_id", "==", item_id).limit(1).get()
                if not query:
                    return jsonify({"error": f"Product {item_id} out of stock or invalid."}), 400
                product = query[0].to_dict()
            else:
                product = doc_ref.to_dict()

            real_price = float(product.get("selling_price", 0))
            secure_subtotal += real_price * quantity
            
            # Rebuild the item with trusted server data
            item.update({
                "price": real_price,
                "brandName": product.get("brandName", ""),
                "sellerName": product.get("sellerName", ""),
                "sellerEmail": product.get("sellerEmail", "")
            })
            enriched_cart.append(item)

        if secure_subtotal <= 0:
            return jsonify({"error": "Order total must be greater than zero."}), 400

        shipping_fee = 149 if secure_subtotal < 1999 else 0
        final_total = secure_subtotal + shipping_fee

        order_data = {
            "email": customer_email,
            "items": enriched_cart,
            "subtotal": secure_subtotal,
            "shipping_fee": shipping_fee,
            "total": final_total,
            "status": "pending",
            "payment_method": payment_method,
            "shippingAddress": shipping_address,
            "created_at": datetime.utcnow().isoformat(),
        }

        # Handle COD
        if payment_method == "COD":
            order_data["order_id"] = f"cod_{int(datetime.now().timestamp())}"
            db.collection("orders").add(order_data)
            logger.info(f"COD Order created: {order_data['order_id']}")
            return jsonify({"status": "success", "payment_method": "COD", "order_id": order_data["order_id"]}), 201

        # Handle Razorpay
        if not razorpay_client:
            return jsonify({"error": "Payment gateway unavailable"}), 503

        razorpay_order = razorpay_client.order.create({
            "amount": int(final_total * 100),
            "currency": "INR",
            "receipt": f"rcpt_{int(datetime.now().timestamp())}"
        })

        order_data["razorpay_order_id"] = razorpay_order["id"]
        db.collection("orders").add(order_data)
        logger.info(f"Razorpay Order created: {razorpay_order['id']}")
        
        return jsonify(razorpay_order), 201

    except Exception as e:
        logger.error(f"Error creating order: {e}", exc_info=True)
        return jsonify({"error": "Failed to process order"}), 500

@app.route("/verify-payment", methods=["POST"])
def verify_payment():
    if db is None:
        return jsonify({"error": "Firebase is not connected."}), 500

    if not razorpay_client or RAZORPAY_KEY_SECRET == "YOUR_SECRET_KEY_HERE":
        return jsonify({"error": "Razorpay is not configured. Set RAZORPAY_KEY_SECRET."}), 500

    try:
        data = request.get_json()

        razorpay_order_id = data.get("razorpay_order_id")
        razorpay_payment_id = data.get("razorpay_payment_id")
        razorpay_signature = data.get("razorpay_signature")

        razorpay_client.utility.verify_payment_signature({
            "razorpay_order_id": razorpay_order_id,
            "razorpay_payment_id": razorpay_payment_id,
            "razorpay_signature": razorpay_signature,
        })

        orders_ref = db.collection("orders").where(
            "razorpay_order_id", "==", razorpay_order_id
        ).limit(1).get()

        if len(orders_ref) > 0:
            doc_id = orders_ref[0].id
            db.collection("orders").document(doc_id).update({
                "status": "paid",
                "payment_id": razorpay_payment_id,
            })

        return jsonify({"status": "Payment verified and saved!"}), 200

    except razorpay.errors.SignatureVerificationError:
        logger.warning("Signature mismatch detected.")
        return jsonify({"error": "Payment signature verification failed."}), 400
    except Exception as e:
        logger.error(f"Error verifying payment: {e}")
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
            # Dynamic Pagination: Allows frontend to pass ?limit=100
            limit = int(request.args.get("limit", 50))
            
            products = []
            docs = db.collection("products").order_by("created_at", direction=firestore.Query.DESCENDING).limit(limit).get()
            
            for doc in docs:
                products.append({**doc.to_dict(), "docId": doc.id})
                
            return jsonify(products), 200
        except Exception as e:
            logger.error(f"Failed to fetch products: {e}")
            return jsonify({"error": "Internal server error"}), 500

    if request.method == "POST":
        try:
            data = request.get_json()
            data["created_at"] = datetime.utcnow().isoformat()
            _, doc_ref = db.collection("products").add(data)
            logger.info(f"Product added by admin: {doc_ref.id}")
            return jsonify({"status": "success", "id": doc_ref.id}), 201
        except Exception as e:
            logger.error(f"Failed to create product: {e}")
            return jsonify({"error": "Failed to create product"}), 500

@app.route("/admin/products/<doc_id>", methods=["PUT", "DELETE"])
@admin_required
def admin_product_detail(doc_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    doc_ref = db.collection("products").document(doc_id)

    if request.method == "PUT":
        try:
            doc_ref.update(request.get_json())
            logger.info(f"Product updated: {doc_id}")
            return jsonify({"status": "success"}), 200
        except Exception as e:
            logger.error(f"Failed to update product {doc_id}: {e}")
            return jsonify({"error": "Update failed"}), 500

    if request.method == "DELETE":
        try:
            doc_ref.delete()
            logger.info(f"Product deleted: {doc_id}")
            return jsonify({"status": "success"}), 200
        except Exception as e:
            logger.error(f"Failed to delete product {doc_id}: {e}")
            return jsonify({"error": "Deletion failed"}), 500

@app.route("/admin/orders", methods=["GET"])
@admin_required
def admin_orders():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        limit = int(request.args.get("limit", 50))
        orders = []
        docs = db.collection("orders").order_by("created_at", direction=firestore.Query.DESCENDING).limit(limit).get()
        
        for doc in docs:
            orders.append({**doc.to_dict(), "id": doc.id})
            
        return jsonify(orders), 200
    except Exception as e:
        logger.error(f"Failed to fetch orders: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/admin/orders/<order_id>", methods=["PUT"])
@admin_required
def update_order(order_id):
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        db.collection("orders").document(order_id).update(request.get_json())
        logger.info(f"Order {order_id} updated")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        logger.error(f"Failed to update order {order_id}: {e}")
        return jsonify({"error": "Update failed"}), 500

@app.route("/admin/customers", methods=["GET"])
@admin_required
def admin_customers():
    if db is None: return jsonify({"error": "Database unavailable"}), 503
    try:
        limit = int(request.args.get("limit", 50))
        customers = []
        docs = db.collection("users").limit(limit).get()
        
        for doc in docs:
            customers.append({**doc.to_dict(), "id": doc.id})
            
        return jsonify(customers), 200
    except Exception as e:
        logger.error(f"Failed to fetch customers: {e}")
        return jsonify({"error": "Internal server error"}), 500

# ==========================================
# 7. RUN THE SERVER
# ==========================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
