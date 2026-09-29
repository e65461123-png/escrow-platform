# -*- coding: utf-8 -*-
"""
نظام 2FA (التحقق بخطوتين) - TOTP
"""
import pyotp
import qrcode
import io
import base64
import secrets
from functools import wraps
from flask import session, jsonify, request


def generate_secret():
    """توليد مفتاح سري جديد"""
    return pyotp.random_base32()


def get_totp(secret):
    """الحصول على كائن TOTP"""
    return pyotp.TOTP(secret)


def verify_code(secret, code):
    """التحقق من الكود"""
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def generate_qr_base64(secret, username, issuer='Escrow'):
    """توليد QR Code كـ base64"""
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name=issuer)
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    return base64.b64encode(buffer.getvalue()).decode()


def require_2fa(f):
    """Decorator لحماية المسارات بـ 2FA"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('2fa_verified'):
            return jsonify({'status': 'ERROR', 'message': '2FA مطلوب', 'require_2fa': True}), 401
        return f(*args, **kwargs)
    return wrapper


def generate_backup_codes(count=10):
    """توليد أكواد احتياطية"""
    return [secrets.token_hex(4).upper() for _ in range(count)]


def setup_routes(app, get_db, _placeholder, login_required):
    """تسجيل مسارات 2FA في التطبيق"""
    
    @app.route('/api/2fa/setup', methods=['POST'])
    @login_required
    def api_2fa_setup():
        username = session.get('user')
        secret = generate_secret()
        
        # خزنه مؤقتاً في الجلسة لحد ما يتأكد
        session['2fa_pending_secret'] = secret
        
        # اعمل QR
        qr_base64 = generate_qr_base64(secret, username)
        
        return jsonify({
            'status': 'OK',
            'secret': secret,
            'qr_code': f'data:image/png;base64,{qr_base64}',
            'message': 'امسح الـ QR بتطبيق Google Authenticator'
        })
    
    
    @app.route('/api/2fa/verify-setup', methods=['POST'])
    @login_required
    def api_2fa_verify_setup():
        username = session.get('user')
        code = request.json.get('code', '').strip()
        secret = session.get('2fa_pending_secret')
        
        if not secret:
            return jsonify({'status': 'ERROR', 'message': 'ابدأ الإعداد الأول'})
        
        if not verify_code(secret, code):
            return jsonify({'status': 'ERROR', 'message': 'كود غلط'})
        
        # فعّل 2FA
        backup_codes = generate_backup_codes()
        
        try:
            c = get_db()
            p = _placeholder()
            c.execute(
                f"UPDATE users SET totp_secret={p}, totp_enabled=1 WHERE username={p}",
                (secret, username)
            )
            try:
                c.commit()
            except:
                pass
            c.close()
        except Exception as e:
            return jsonify({'status': 'ERROR', 'message': str(e)})
        
        session.pop('2fa_pending_secret', None)
        session['2fa_verified'] = True
        
        return jsonify({
            'status': 'OK',
            'message': 'تم تفعيل 2FA',
            'backup_codes': backup_codes
        })
    
    
    @app.route('/api/2fa/verify', methods=['POST'])
    def api_2fa_verify():
        username = request.json.get('username')
        code = request.json.get('code', '').strip()
        
        if not username or not code:
            return jsonify({'status': 'ERROR', 'message': 'بيانات ناقصة'})
        
        try:
            c = get_db()
            p = _placeholder()
            user = c.execute(
                f"SELECT totp_secret, totp_enabled FROM users WHERE username={p}",
                (username,)
            ).fetchone()
            c.close()
            
            if not user or not user['totp_enabled']:
                return jsonify({'status': 'ERROR', 'message': '2FA غير مفعّل'})
            
            if not verify_code(user['totp_secret'], code):
                return jsonify({'status': 'ERROR', 'message': 'كود غلط'})
            
            session['2fa_verified'] = True
            return jsonify({'status': 'OK'})
        except Exception as e:
            return jsonify({'status': 'ERROR', 'message': str(e)})
    
    
    @app.route('/api/2fa/disable', methods=['POST'])
    @login_required
    def api_2fa_disable():
        username = session.get('user')
        code = request.json.get('code', '').strip()
        
        try:
            c = get_db()
            p = _placeholder()
            user = c.execute(
                f"SELECT totp_secret FROM users WHERE username={p}",
                (username,)
            ).fetchone()
            
            if not user or not user['totp_secret']:
                c.close()
                return jsonify({'status': 'ERROR', 'message': '2FA غير مفعّل'})
            
            if not verify_code(user['totp_secret'], code):
                c.close()
                return jsonify({'status': 'ERROR', 'message': 'كود غلط'})
            
            c.execute(
                f"UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE username={p}",
                (username,)
            )
            try:
                c.commit()
            except:
                pass
            c.close()
            
            session.pop('2fa_verified', None)
            return jsonify({'status': 'OK', 'message': 'تم إلغاء 2FA'})
        except Exception as e:
            return jsonify({'status': 'ERROR', 'message': str(e)})
    
    
    @app.route('/api/2fa/status')
    @login_required
    def api_2fa_status():
        username = session.get('user')
        try:
            c = get_db()
            p = _placeholder()
            user = c.execute(
                f"SELECT totp_enabled FROM users WHERE username={p}",
                (username,)
            ).fetchone()
            c.close()
            return jsonify({
                'status': 'OK',
                'enabled': bool(user and user['totp_enabled'])
            })
        except Exception as e:
            return jsonify({'status': 'ERROR', 'message': str(e)})
    
    
    print('[2FA] تم تسجيل المسارات بنجاح')
