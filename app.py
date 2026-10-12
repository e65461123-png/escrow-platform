import os
import uuid
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())

# ==========================================
# 1. إعدادات قاعدة البيانات (Database Setup)
# ==========================================
database_url = os.environ.get('DATABASE_URL')

# إصلاح: استخدام psycopg2 (النسخة 2) لضمان الاستقرار على Render
if database_url and database_url.startswith('postgresql://'):
    database_url = database_url.replace('postgresql://', 'postgresql+psycopg2://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ==========================================
# 2. تعريف الجداول (Database Models)
# ==========================================
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    wallet = db.relationship('Wallet', backref='user', uselist=False)

class Wallet(db.Model):
    __tablename__ = 'wallets'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    balance_usd = db.Column(db.Float, default=0.0)
    wallet_address = db.Column(db.String(100), unique=True, nullable=False)

class Escrow(db.Model):
    __tablename__ = 'escrows'
    id = db.Column(db.String(100), primary_key=True)
    buyer_email = db.Column(db.String(120), nullable=False)
    seller_email = db.Column(db.String(120), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default="LOCKED") 

# إنشاء الجداول تلقائياً عند بدء التطبيق
with app.app_context():
    db.create_all()

# ==========================================
# 3. المسارات (Routes)
# ==========================================

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "status": "online",
        "system": "Secure Enterprise Escrow Platform",
        "security": "Encrypted & Protected"
    }), 200

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json() or {}
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"status": "error", "message": "Email and password are required"}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({"status": "error", "message": "User already exists"}), 400

        hashed_password = generate_password_hash(password)
        
        new_user = User(email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.flush()

        new_wallet = Wallet(
            user_id=new_user.id,
            balance_usd=0.0,
            wallet_address=f"0x{uuid.uuid4().hex}"
        )
        db.session.add(new_wallet)
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "User registered securely",
            "wallet_address": new_wallet.wallet_address
        }), 201

    except Exception as e:
        db.session.rollback()
        import traceback; traceback.print_exc(); return jsonify({"status": "error", "message": str(e)}), 500

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

        return jsonify({
            "status": "success",
            "message": "Login successful",
            "access_token": access_token,
            "wallet": {
                "balance_usd": user.wallet.balance_usd,
                "wallet_address": user.wallet.wallet_address
            }
        }), 200

    except Exception as e:
        import traceback; traceback.print_exc(); return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/wallet/balance', methods=['GET'])
@jwt_required()
def get_balance():
    try:
        current_user_email = get_jwt_identity()
        user = User.query.filter_by(email=current_user_email).first()

        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        return jsonify({
            "status": "success",
            "wallet": {
                "balance_usd": user.wallet.balance_usd,
                "wallet_address": user.wallet.wallet_address
            }
        }), 200

    except Exception as e:
        import traceback; traceback.print_exc(); return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/escrow/create', methods=['POST'])
@jwt_required()
def create_escrow():
    try:
        data = request.get_json() or {}
        buyer_email = get_jwt_identity()
        seller_email = data.get('seller')
        
        try:
            amount = float(data.get('amount', 0))
        except (ValueError, TypeError):
            return jsonify({"status": "error", "message": "Invalid amount format"}), 400

        if amount <= 0:
            return jsonify({"status": "error", "message": "Amount must be greater than zero"}), 400

        buyer_wallet = Wallet.query.join(User).filter(User.email == buyer_email).first()
        seller_wallet = Wallet.query.join(User).filter(User.email == seller_email).first()

        if not buyer_wallet or not seller_wallet:
            return jsonify({"status": "error", "message": "Buyer or Seller wallet missing"}), 400

        if buyer_wallet.balance_usd < amount:
            return jsonify({"status": "error", "message": "Insufficient funds"}), 400

        buyer_wallet.balance_usd -= amount
        
        tx_id = f"escrow_{uuid.uuid4().hex}"
        new_escrow = Escrow(
            id=tx_id,
            buyer_email=buyer_email,
            seller_email=seller_email,
            amount=amount,
            status="LOCKED"
        )
        
        db.session.add(new_escrow)
        db.session.commit()

        return jsonify({
            "status": "success",
            "transaction_id": tx_id,
            "message": "Funds locked securely in Escrow"
        }), 201

    except Exception as e:
        db.session.rollback()
        import traceback; traceback.print_exc(); return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/escrow/release', methods=['POST'])
@jwt_required()
def release_escrow():
    try:
        data = request.get_json() or {}
        tx_id = data.get('transaction_id')
        current_user_email = get_jwt_identity()

        tx = Escrow.query.get(tx_id)
        if not tx or tx.status != "LOCKED":
            return jsonify({"status": "error", "message": "Invalid or already completed transaction"}), 400

        if tx.buyer_email != current_user_email:
            return jsonify({"status": "error", "message": "Unauthorized to release these funds"}), 403

        seller_wallet = Wallet.query.join(User).filter(User.email == tx.seller_email).first()
        if not seller_wallet:
            return jsonify({"status": "error", "message": "Seller wallet not found"}), 404

        seller_wallet.balance_usd += tx.amount
        tx.status = "RELEASED"
        
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Funds released to seller successfully"
        }), 200

    except Exception as e:
        db.session.rollback()
        import traceback; traceback.print_exc(); return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
