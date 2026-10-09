#!/bin/bash

echo "🚀 بدء إصلاح المشروع..."

# ==========================================
# 1. إصلاح ملف requirements.txt
# ==========================================
echo "📦 تحديث requirements.txt..."
cat << 'REQ' > requirements.txt
Flask>=3.0.0
Werkzeug>=3.0.0
gunicorn>=21.2.0
psycopg2-binary>=2.9.9
pyotp>=2.9.0
qrcode[pil]>=7.4.2
pillow>=10.0.0
requests>=2.31.0
python-dotenv>=1.0.0
Flask-Limiter>=3.5.0
Flask-Migrate>=4.0.5
Flask-WTF>=1.2.1
fpdf2>=2.7.8
groq>=0.4.0
pywebpush>=2.0.0
REQ

# ==========================================
# 2. إصلاح ملف render.yaml
# ==========================================
echo "☁️ تحديث render.yaml..."
cat << 'YAML' > render.yaml
services:
  - type: web
    name: secure-escrow-platform
    env: python
    region: frankfurt
    plan: free
    buildCommand: pip install -r requirements.txt
    startCommand: gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 2 --timeout 60
    envVars:
      - key: PYTHON_VERSION
        value: 3.11.0
      - key: SECRET_KEY
        generateValue: true
      - key: FLASK_ENV
        value: production
      - key: RENDER
        value: "true"
      - key: MASTER_OWNER
        value: EssamElkomy369
      - key: VAULT_PIN
        sync: false
      - key: OWNER_PASSWORD
        sync: false
      - key: DATABASE_URL
        sync: false
      - key: RESEND_API_KEY
        sync: false
      - key: GROQ_API_KEY
        sync: false
YAML

# ==========================================
# 3. إنشاء ملف إعدادات الأمان
# ==========================================
echo "🔒 إنشاء security_config.py..."
cat << 'SEC' > security_config.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

csrf = CSRFProtect()

def init_security(app):
    limiter.init_app(app)
    csrf.init_app(app)

    # إعدادات تأمين الكوكيز
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=3600,
        WTF_CSRF_TIME_LIMIT=None
    )
    return app
SEC

# ==========================================
# 4. تعديل app.py (إضافة الأمان)
# ==========================================
echo "⚙️ تحديث app.py..."
if ! grep -q "from security_config import" app.py; then
    # إضافة الاستيراد في بداية الملف
    sed -i '1i from security_config import init_security, limiter' app.py

    # إضافة استدعاء التهيئة بعد إنشاء app
    if grep -q "app = Flask(__name__)" app.py; then
        sed -i '/app = Flask(__name__)/a init_security(app)' app.py
    else
        echo "⚠️ تحذير: لم أجد 'app = Flask(__name__)' في app.py. أضف init_security(app) يدوياً."
    fi
else
    echo "ℹ️ app.py يحتوي بالفعل على إعدادات الأمان."
fi

# ==========================================
# 5. إنشاء ملف .env.example محدث
# ==========================================
echo "📝 تحديث .env.example..."
cat << 'ENV' > .env.example
SECRET_KEY=your-super-secret-key-change-me
FLASK_ENV=production
DATABASE_URL=postgresql://user:password@host:5432/dbname
RESEND_API_KEY=your_resend_api_key
GROQ_API_KEY=your_groq_api_key
MASTER_OWNER=EssamElkomy369
VAULT_PIN=your_vault_pin
OWNER_PASSWORD=your_owner_password
ENV

echo "✅ تم الانتهاء من جميع التعديلات بنجاح!"
echo "📌 الخطوات التالية:"
echo "1. rفع التعديلات: git add . && git commit -m 'security fixes' && git push"
echo "2. أضف المتغيرات (RESEND_API_KEY, GROQ_API_KEY, DATABASE_URL) في لوحة Render"
echo "3. انتظر إعادة النشر على Render"
