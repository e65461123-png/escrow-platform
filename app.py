from flask import Flask, request, jsonify

app = Flask(__name__)

# قاعدة بيانات مؤقتة في الذاكرة لتخزين أرصدة المحافظ
wallets_db = {
    "user@example.com": {"balance": 100.0, "currency": "USD"}
}

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json() or {}
        email = data.get('email', 'user@example.com')
        return jsonify({
            "status": "success", 
            "message": "login successful",
            "user": email
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/wallet', methods=['POST'])
def get_wallet():
    try:
        data = request.get_json() or {}
        email = data.get('email', 'user@example.com')
        
        # جلب بيانات المحفظة أو إنشاء محفظة افتراضية برصيد صفر
        wallet_info = wallets_db.get(email, {"balance": 0.0, "currency": "USD"})
        
        return jsonify({
            "status": "success",
            "wallet": wallet_info
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
