import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# ==========================================
# 1. المكونات الأساسية وتخزين البيانات
# ==========================================
# قاعدة بيانات داخل الذاكرة (مجهزة للربط المستقبلي بـ PostgreSQL)
USERS_DB = {}
WALLETS_DB = {}
ESCROW_TRANSACTIONS = {}

# ==========================================
# 2. مسارات المصادقة والمستخدمين (Auth Routes)
# ==========================================
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json() or {}
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"status": "error", "message": "Email and password required"}), 400

        if email in USERS_DB:
            return jsonify({"status": "error", "message": "User already exists"}), 400

        USERS_DB[email] = {"password": password}
        WALLETS_DB[email] = {"balance_usd": 0.0, "token_balance": 0.0, "wallet_address": f"0x{os.urandom(20).hex()}"}

        return jsonify({
            "status": "success",
            "message": "User registered successfully",
            "wallet_address": WALLETS_DB[email]["wallet_address"]
        }), 201
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json() or {}
        email = data.get('email')
        password = data.get('password')

        user = USERS_DB.get(email)
        if not user or user['password'] != password:
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401

        return jsonify({
            "status": "success",
            "message": "Login successful",
            "user": email,
            "wallet": WALLETS_DB.get(email)
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ==========================================
# 3. مسارات المحفظة والعملة الرقمية (Wallet)
# ==========================================
@app.route('/api/wallet/balance', methods=['POST'])
def get_balance():
    try:
        data = request.get_json() or {}
        email = data.get('email')

        wallet = WALLETS_DB.get(email)
        if not wallet:
            return jsonify({"status": "error", "message": "Wallet not found"}), 444

        return jsonify({
            "status": "success",
            "wallet": wallet
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ==========================================
# 4. مسارات منصة الضمان (Escrow Engine)
# ==========================================
@app.route('/api/escrow/create', methods=['POST'])
def create_escrow():
    try:
        data = request.get_json() or {}
        buyer = data.get('buyer')
        seller = data.get('seller')
        amount = float(data.get('amount', 0))

        if buyer not in WALLETS_DB or seller not in WALLETS_DB:
            return jsonify({"status": "error", "message": "Buyer or Seller wallet missing"}), 400

        if WALLETS_DB[buyer]['balance_usd'] < amount:
            return jsonify({"status": "error", "message": "Insufficient funds"}), 400

        # حجز المبلغ في الضمان
        WALLETS_DB[buyer]['balance_usd'] -= amount
        tx_id = f"escrow_{len(ESCROW_TRANSACTIONS) + 1}"
        ESCROW_TRANSACTIONS[tx_id] = {
            "buyer": buyer,
            "seller": seller,
            "amount": amount,
            "status": "LOCKED"
        }

        return jsonify({
            "status": "success",
            "transaction_id": tx_id,
            "message": "Funds locked in Escrow"
        }), 201
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/escrow/release', methods=['POST'])
def release_escrow():
    try:
        data = request.get_json() or {}
        tx_id = data.get('transaction_id')

        tx = ESCROW_TRANSACTIONS.get(tx_id)
        if not tx or tx['status'] != "LOCKED":
            return jsonify({"status": "error", "message": "Invalid or completed transaction"}), 400

        # تحويل الأموال إلى البائع
        seller = tx['seller']
        WALLETS_DB[seller]['balance_usd'] += tx['amount']
        tx['status'] = "RELEASED"

        return jsonify({
            "status": "success",
            "message": "Funds released to seller successfully"
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ==========================================
# 5. تشغيل التطبيق
# ==========================================
if __name__ == '__main__':
    app.run(debug=True)
