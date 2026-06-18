# ==========================================
# 1. IMPORTS
# ==========================================
import os
import json
from datetime import datetime

from flask import Flask, request, jsonify
from flask_cors import CORS
import razorpay
import firebase_admin
from firebase_admin import credentials, firestore
 
# ==========================================
# 2. INITIALIZE FLASK
# ==========================================
app = Flask(__name__)
CORS(app)
 
# ==========================================
# 3. SETUP DATABASE & PAYMENTS
# ==========================================
FIREBASE_KEY_PATH = os.getenv("FIREBASE_KEY_PATH", "firebase-key.json")
firebase_project_id = None

try:
    if os.path.exists(FIREBASE_KEY_PATH):
        with open(FIREBASE_KEY_PATH, "r", encoding="utf-8") as key_file:
            firebase_project_id = json.load(key_file).get("project_id")

    cred = credentials.Certificate(FIREBASE_KEY_PATH)
    if not firebase_admin._apps:
        firebase_admin.initialize_app(cred)

    db = firestore.client()
    print(f"Firebase initialized successfully. Project: {firebase_project_id}")
except Exception as e:
    print("Firebase initialization failed:", e)
    print(f"Make sure {FIREBASE_KEY_PATH} is in the same folder as this server file.")
    db = None
 
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "rzp_test_SvVCY9dpYnL1Kq")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "YOUR_SECRET_KEY_HERE")

try:
    razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    print("Razorpay client initialized.")
except Exception as e:
    print("Razorpay initialization failed:", e)
    razorpay_client = None
  
# ==========================================
# 4. TEST ROUTES
# ==========================================
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "server": "running",
        "firebase_connected": db is not None,
        "firebase_project_id": firebase_project_id,
        "razorpay_client_created": razorpay_client is not None,
        "razorpay_secret_set": RAZORPAY_KEY_SECRET != "YOUR_SECRET_KEY_HERE",
    })
 
@app.route("/test-firebase", methods=["GET"])
def test_firebase():
    if db is None:
        return jsonify({"error": "Firebase is not connected. Check server terminal logs."}), 500

    test_data = {
        "source": "flask-server",
        "status": "connected",
        "checked_at": datetime.utcnow().isoformat(),
    }
    db.collection("connection_tests").document("server").set(test_data)

    return jsonify({
        "status": "Firebase write successful",
        "collection": "connection_tests",
        "document": "server",
        "data": test_data,
    })
 
# ==========================================
# 5. ORDER ROUTES (Customer Facing)
# ==========================================
@app.route("/create-order", methods=["POST"])
def create_order():
    if db is None:
        return jsonify({"error": "Firebase is not connected. Check terminal logs."}), 500

    try:
        data = request.get_json()
        cart = data.get("cart", [])
        customer_email = data.get("customer", "guest@jambawear.com")
          
        shipping_address = data.get("shippingAddress") or data.get("shipping_address", {})
        payment_method = data.get("payment_method", "Razorpay")

        secure_subtotal = 0

        for item in cart:
            item_id = str(item.get("id"))
            quantity = int(item.get("quantity", 1))
            product = None

            doc_ref = db.collection("products").document(item_id).get()
            if doc_ref.exists:
                product = doc_ref.to_dict()
            else:
                query = db.collection("products").where("item_id", "==", item_id).limit(1).get()
                if len(query) > 0:
                    product = query[0].to_dict()

            if product:
                real_price = float(product.get("selling_price", 0))
                secure_subtotal += real_price * quantity
                
                # 🔥 THE FIX: Stamp seller data onto the order item
                item["brandName"] = product.get("brandName", "")
                item["sellerName"] = product.get("sellerName", "")
                item["sellerId"] = product.get("sellerId", "")
                
            else:
                raise Exception(f"Item {item_id} not found in database.")

        if secure_subtotal == 0:
            raise Exception("Cannot create an order with a total of 0.")

        shipping_fee = 149 if secure_subtotal < 1999 else 0
        final_total = secure_subtotal + shipping_fee

        if payment_method == "COD":
            cod_order_id = f"cod_{int(datetime.now().timestamp())}"

            db.collection("orders").add({
                "order_id": cod_order_id,
                "email": customer_email,
                "items": cart,
                "subtotal": secure_subtotal,
                "shipping_fee": shipping_fee,
                "total": final_total,
                "status": "pending",
                "payment_method": "COD",
                "shippingAddress": shipping_address,
                "shipping_address": shipping_address,
                "created_at": datetime.utcnow().isoformat(),
            })

            return jsonify({
                "status": "success",
                "payment_method": "COD",
                "order_id": cod_order_id,
            })

        if not razorpay_client or RAZORPAY_KEY_SECRET == "YOUR_SECRET_KEY_HERE":
            return jsonify({"error": "Razorpay is not configured. Set RAZORPAY_KEY_SECRET."}), 500

        amount_in_paise = int(final_total * 100)
        order_options = {
            "amount": amount_in_paise,
            "currency": "INR",
            "receipt": f"rcpt_{int(datetime.now().timestamp())}",
        }

        order = razorpay_client.order.create(data=order_options)

        db.collection("orders").add({
            "razorpay_order_id": order["id"],
            "email": customer_email,
            "items": cart,
            "subtotal": secure_subtotal,
            "shipping_fee": shipping_fee,
            "total": final_total,
            "status": "pending",
            "payment_method": "Razorpay",
            "shippingAddress": shipping_address,
            "shipping_address": shipping_address,
            "created_at": datetime.utcnow().isoformat(),
        })

        return jsonify(order)

    except Exception as e:
        print("Error creating order:", e)
        return jsonify({"error": str(e)}), 500
 
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
        print("Signature mismatch detected.")
        return jsonify({"error": "Payment signature verification failed."}), 400
    except Exception as e:
        print("Error verifying payment:", e)
        return jsonify({"error": str(e)}), 500

# ==========================================
# 6. ADMIN ROUTES (Unified Backend Architecture)
# ==========================================

# --- PRODUCTS ---
@app.route("/admin/products", methods=["GET", "POST"])
def admin_products():
    if db is None: return jsonify({"error": "Firebase disconnected"}), 500
    
    if request.method == "GET":
        try:
            products = []
            docs = db.collection("products").get()
            for doc in docs:
                data = doc.to_dict()
                data["docId"] = doc.id
                products.append(data)
            return jsonify(products), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    if request.method == "POST":
        try:
            data = request.get_json()
            db.collection("products").add(data)
            return jsonify({"status": "Product Added"}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route("/admin/products/<doc_id>", methods=["PUT", "DELETE"])
def admin_product_detail(doc_id):
    if db is None: return jsonify({"error": "Firebase disconnected"}), 500

    if request.method == "PUT":
        try:
            data = request.get_json()
            db.collection("products").document(doc_id).update(data)
            return jsonify({"status": "Product Updated"}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    if request.method == "DELETE":
        try:
            db.collection("products").document(doc_id).delete()
            return jsonify({"status": "Product Deleted"}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500

# --- ORDERS ---
@app.route("/admin/orders", methods=["GET"])
def admin_orders():
    if db is None: return jsonify({"error": "Firebase disconnected"}), 500
    try:
        orders = []
        docs = db.collection("orders").get()
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            orders.append(data)
        return jsonify(orders), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/orders/<order_id>", methods=["PUT"])
def update_order(order_id):
    if db is None: return jsonify({"error": "Firebase disconnected"}), 500
    try:
        data = request.get_json()
        db.collection("orders").document(order_id).update(data)
        return jsonify({"status": "Order Updated"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- CUSTOMERS ---
@app.route("/admin/customers", methods=["GET"])
def admin_customers():
    if db is None: return jsonify({"error": "Firebase disconnected"}), 500
    try:
        customers = []
        docs = db.collection("users").get()
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            customers.append(data)
        return jsonify(customers), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# 7. RUN THE SERVER
# ==========================================
if __name__ == "__main__":
    app.run(port=5000, debug=True, use_reloader=False)
