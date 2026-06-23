#  ==========================================
# 6. ADMIN ROUTES (Unified Backend Architecture)
# ==========================================

# --- PRODUCTS ---
@app.route("/admin/products", methods=["GET", "POST"])
def admin_products():
    if db is None: return jsonify({"error": "Firebase disconnected"}), 500
    
    if request.method == "GET":
        try:
            products = []
            # 🚀 UPDATED: Fetch only the 50 most recent products
            docs = db.collection("products").order_by("created_at", direction=firestore.Query.DESCENDING).limit(50).get()
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
        # 🚀 UPDATED: Fetch only the 50 most recent orders
        docs = db.collection("orders").order_by("created_at", direction=firestore.Query.DESCENDING).limit(50).get()
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
        # 🚀 UPDATED: Capped to 50 users (no order_by to avoid hiding old users missing timestamps)
        docs = db.collection("users").limit(50).get()
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            customers.append(data)
        return jsonify(customers), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
