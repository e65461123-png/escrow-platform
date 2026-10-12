import os
import uuid
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# إعدادات قاعدة البيانات والأمان
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///escrow.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', os.urandom(32).hex())

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ==========================================
# نماذج قاعدة البيانات (Database Models)
# ==========================================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    wallet = db.relationship('Wallet', backref='user', uselist=False, cascade="all, delete-orphan")

class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    balance_usd = db.Column(db.Float, default=0.0)
    wallet_address = db.Column(db.String(100), unique=True, nullable=False)

class EscrowTransaction(db.Model):
    id = db.Column(db.String(100), primary_key=True)
    buyer_email = db.Column(db.String(120), nullable=False)
    seller_email = db.Column(db.String(120), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default="LOCKED")

# إنشاء الجداول تلقائياً عند التشغيل
with app.app_context():
    db.create_all()

# ==========================================
# المسار الرئيسي
# ==========================================
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "status": "online",
        "system": "Secure Enterprise Escrow Platform",
        "database": "Persistent Database Active",
        "security": "JWT Protected"
    }), 200

# ==========================================
# مصادقة المستخدمين (Auth)
# ==========================================
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json() or {}
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"status": "error", "message": "Email and password required"}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({"status": "error", "message": "User already exists"}), 400

        hashed_password = generate_password_hash(password)
        new_user = User(email=email, password_hash=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()

        new_wallet = Wallet(
            user_id=new_user.id,
            balance_usd=100.0,  # رصيد تجريبي افتراضي للبدء
            wallet_address=f"0x{uuid.uuid4().hex}"
        )
        db.session.add(new_wallet)
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "User registered successfully",
            "wallet_address": new_wallet.wallet_address
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json() or {}
        email = data.get('email')
        password = data.get('password')

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401

        access_token = create_access_token(identity=email)
        wallet = Wallet.query.filter_by(user_id=user.id).first()

        return jsonify({
            "status": "success",
            "access_token": access_token,
            "wallet": {
                "balance_usd": wallet.balance_usd,
                "wallet_address": wallet.wallet_address
            }
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ==========================================
# إدارة المحفظة (Wallet)
# ==========================================
@app.route('/api/wallet/balance', methods=['GET'])
@jwt_required()
def get_balance():
    try:
        current_user_email = get_jwt_identity()
        user = User.query.filter_by(email=current_user_email).first()
        wallet = Wallet.query.filter_by(user_id=user.id).first()

        return jsonify({
            "status": "success",
            "wallet": {
                "balance_usd": wallet.balance_usd,
                "wallet_address": wallet.wallet_address
            }
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ==========================================
# نظام الضمان (Escrow Engine)
# ==========================================
@app.route('/api/escrow/create', methods=['POST'])
@jwt_required()
def create_escrow():
    try:
        current_user_email = get_jwt_identity()
        data = request.get_json() or {}
        seller_email = data.get('seller')
        
        try:
            amount = float(data.get('amount', 0))
        except (ValueError, TypeError):
            return jsonify({"status": "error", "message": "Invalid amount format"}), 400

        if amount <= 0:
            return jsonify({"status": "error", "message": "Amount must be greater than zero"}), 400

        buyer_user = User.query.filter_by(email=current_user_email).first()
        seller_user = User.query.filter_by(email=seller_email).first()

        if not seller_user:
            return jsonify({"status": "error", "message": "Seller not found"}), 404

        buyer_wallet = Wallet.query.filter_by(user_id=buyer_user.id).first()
        seller_wallet = Wallet.query.filter_by(user_id=seller_user.id).first()

        if buyer_wallet.balance_usd < amount:
            return jsonify({"status": "error", "message": "Insufficient funds"}), 400

        # خصم الأموال وحجزها
        buyer_wallet.balance_usd -= amount
        tx_id = f"escrow_{uuid.uuid4().hex}"
        
        new_tx = EscrowTransaction(
            id=tx_id,
            buyer_email=current_user_email,
            seller_email=seller_email,
            amount=amount,
            status="LOCKED"
        )
        
        db.session.add(new_tx)
        db.session.commit()

        return jsonify({
            "status": "success",
            "transaction_id": tx_id,
            "message": "Funds locked securely in Escrow"
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/escrow/release', methods=['POST'])
@jwt_required()
def release_escrow():
    try:
        current_user_email = get_jwt_identity()
        data = request.get_json() or {}
        tx_id = data.get('transaction_id')

        tx = EscrowTransaction.query.filter_by(id=tx_id).first()
        if not tx or tx.status != "LOCKED":
            return jsonify({"status": "error", "message": "Invalid or completed transaction"}), 400

        # التأكد أن المشتري فقط أو الأطراف المصرح لها تقوم بالتحرير
        if tx.buyer_email != current_user_email:
            return jsonify({"status": "error", "message": "Unauthorized action"}), 403

        seller_user = User.query.filter_by(email=tx.seller_email).first()
        seller_wallet = Wallet.query.filter_by(user_id=seller_user.id).first()

        seller_wallet.balance_usd += tx.amount
        tx.status = "RELEASED"
        
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Funds released to seller successfully"
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
