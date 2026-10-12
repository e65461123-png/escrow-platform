from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
         ضع منطق التحقق هنا #
        return jsonify({"status": "success", "message": "تم تسجيل الدخول بنجاح"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
