# -*- coding: utf-8 -*-
"""منصة الضمان المالي الآمن - Enterprise Escrow Platform"""
import os, re, threading, time, secrets, sqlite3, csv, io as _io
from functools import wraps
from datetime import datetime, timedelta
from pg_adapter import PGConnection
from security_hardening import ThreatDetector, EncryptedVault, scan_directory, scan_file
from flask import Flask, jsonify, request, render_template_string, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
# 2FA Import
try:
    from two_factor import setup_routes as setup_2fa_routes
except ImportError:
    setup_2fa_routes = None

# 2FA
# ============ Config ============
def _load_env():
    p = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(p):
        with open(p, 'r') as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    if k not in os.environ: os.environ[k] = v
_load_env()

app = Flask(__name__)
IS_PRODUCTION = bool(os.environ.get('RENDER')) or os.environ.get('FLASK_ENV') == 'production'

_SK = os.environ.get('SECRET_KEY')
if not _SK:
    if IS_PRODUCTION: raise RuntimeError('SECRET_KEY required')
    _SK = secrets.token_hex(32)
app.secret_key = _SK
app.config.update(
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=2*1024*1024,
)

DATABASE = 'enterprise_escrow.db'

# PostgreSQL
DATABASE_URL = os.environ.get('DATABASE_URL', '')
if not DATABASE_URL:
    try:
        p = os.path.join(os.path.dirname(__file__), '.env.db')
        if os.path.exists(p):
            with open(p, 'r') as f:
                DATABASE_URL = f.read().strip()
    except: pass
USE_POSTGRES = bool(DATABASE_URL)
MASTER_OWNER = os.environ.get('MASTER_OWNER', 'EssamElkomy369')
VAULT_PIN = os.environ.get('VAULT_PIN')
if not VAULT_PIN:
    if IS_PRODUCTION: raise RuntimeError('VAULT_PIN required')
    VAULT_PIN = '000000'
GMAIL_USER = os.environ.get('GMAIL_USER', '')
GMAIL_PASS = os.environ.get('GMAIL_PASS', '')
TG_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
RESEND_FROM = os.environ.get('RESEND_FROM', 'onboarding@resend.dev')
AI_API_KEY = os.environ.get('AI_API_KEY', '')
AI_PROVIDER = os.environ.get('AI_PROVIDER', 'groq').lower()
AI_MODEL = os.environ.get('AI_MODEL', 'llama-3.3-70b-versatile')
TG_CHAT = os.environ.get('TELEGRAM_CHAT_ID', '')

MAX_ESCROW = 10000.0
DAILY_LIMIT = 50000.0
MAX_ACTIVE = 10
COMMISSION_RATE = 2.0
PAGE_SIZE = 20

db_lock = threading.Lock()
login_attempts, register_attempts = {}, {}
banned_ips = {}
last_cleanup = time.time()
threat = ThreatDetector()
THREAT_DETECTOR_ENABLED = os.environ.get("THREAT_ENABLED", "0") == "1"

# ============ DB ============
def get_db():
    if USE_POSTGRES:
        return PGConnection(DATABASE_URL)
    c = sqlite3.connect(DATABASE, timeout=30, isolation_level=None, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA journal_mode=WAL')
    c.execute('PRAGMA foreign_keys=ON')
    c.execute('PRAGMA busy_timeout=8000')
    return c

def init_db():




    c = get_db(); cur = c.cursor()
    try:
        cur.execute('BEGIN IMMEDIATE')
        cur.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
            balance REAL DEFAULT 500.0, role TEXT DEFAULT 'CLIENT',
            status TEXT DEFAULT 'ACTIVE', kyc_status TEXT DEFAULT 'NONE',
            referral_code TEXT, email TEXT, trust_score INTEGER DEFAULT 100,
            successful_deals INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS escrows (id INTEGER PRIMARY KEY AUTOINCREMENT,
            seller TEXT NOT NULL, buyer TEXT, amount REAL NOT NULL,
            currency TEXT DEFAULT 'USD', status TEXT DEFAULT 'PENDING',
            dispute_reason TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL, type TEXT NOT NULL, amount REAL NOT NULL,
            note TEXT DEFAULT '', timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL, username TEXT, ip TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS kyc_submissions (id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL, full_name TEXT, id_number TEXT,
            status TEXT DEFAULT 'PENDING', submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT,
            escrow_id INTEGER NOT NULL, sender TEXT NOT NULL, body TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL, title TEXT NOT NULL, body TEXT DEFAULT '',
            is_read INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY AUTOINCREMENT,
            escrow_id INTEGER NOT NULL, reviewer TEXT NOT NULL, reviewee TEXT NOT NULL,
            rating INTEGER NOT NULL, comment TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS milestones (id INTEGER PRIMARY KEY AUTOINCREMENT,
            escrow_id INTEGER NOT NULL, title TEXT NOT NULL, amount REAL NOT NULL,
            status TEXT DEFAULT 'PENDING', order_num INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY AUTOINCREMENT,
            escrow_id INTEGER NOT NULL, uploader TEXT NOT NULL, content TEXT NOT NULL,
            note TEXT DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('''CREATE TABLE IF NOT EXISTS treasury (id INTEGER PRIMARY KEY AUTOINCREMENT,
            balance REAL DEFAULT 0.0, total_commission REAL DEFAULT 0.0,
            total_locked REAL DEFAULT 0.0, total_released REAL DEFAULT 0.0,
            total_refunded REAL DEFAULT 0.0, commission_rate REAL DEFAULT 2.0,
            auto_release_days INTEGER DEFAULT 7,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_tx_user ON transactions(username)')
        cur.execute('CREATE INDEX IF NOT EXISTS idx_esc_status ON escrows(status)')
        cur.execute("SELECT COUNT(*) as n FROM treasury")
        if cur.fetchone()['n'] == 0:
            cur.execute("INSERT INTO treasury (balance, commission_rate, auto_release_days) VALUES (0.0, 2.0, 7)")
        cur.execute("SELECT * FROM users WHERE username = ?", (MASTER_OWNER,))
        if not cur.fetchone():
            h = generate_password_hash('EssamElkomy369')
            cur.execute("INSERT INTO users (username, password_hash, balance, role, status, referral_code) VALUES (?,?,?,?,?,?)",
                       (MASTER_OWNER, h, 100000.0, 'OWNER', 'ACTIVE', 'OWNER001'))
        cur.execute('COMMIT')
    except Exception as e:
        cur.execute('ROLLBACK'); print(f'[INIT] {e}')
    finally: c.close()



# ============ Utils ============
def log_event(ev, u=None):
    try:
        c = get_db()
        c.execute("INSERT INTO logs (event, username, ip) VALUES (?,?,?)",
                 (ev, u, request.remote_addr if request else 'N/A'))
        c.close()
    except: pass

def notify(u, title, body=''):
    try:
        c = get_db()
        c.execute("INSERT INTO notifications (username, title, body) VALUES (?,?,?)", (u, title, body))
        c.close()
    except: pass
    if u == MASTER_OWNER:
        try: send_telegram(f'<b>{title}</b>\n{body}')
        except: pass
    try: send_email_to_user(u, title, f'<p>{body}</p>')
    except: pass

def valid_user(u):
    return u and 3 <= len(u) <= 30 and re.match(r'^[a-zA-Z0-9_]+$', u)

def valid_pass(p):
    if len(p) < 8: return False, 'كلمة المرور 8+ أحرف'
    if not re.search(r'[A-Za-z]', p): return False, 'يجب حرف'
    if not re.search(r'\d', p): return False, 'يجب رقم'
    return True, 'OK'

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if 'user' not in session:
            return jsonify({'status': 'ERROR', 'message': 'سجل الدخول'})
        return f(*a, **k)
    return w

def is_admin():
    uid = session.get('user_id')
    if not uid: return False
    try:
        c = get_db()
        u = c.execute("SELECT role, status FROM users WHERE id=?", (uid,)).fetchone()
        c.close()
        return u and u['role'] == 'OWNER' and u['status'] == 'ACTIVE'
    except: return False

def vault_unlocked():
    return session.get('user_id') and session.get('vault_ok') is True

def check_limit(store, key, mx, win):
    now = time.time()
    store.setdefault(key, [])
    store[key] = [t for t in store[key] if now - t < win]
    if len(store[key]) >= mx: return False
    store[key].append(now)
    return True

def ip_banned(ip):
    if ip not in banned_ips: return False
    if time.time() > banned_ips[ip]:
        del banned_ips[ip]; return False
    return True

def ban_ip(ip, m=30): banned_ips[ip] = time.time() + m*60

def client_ip():
    return (request.headers.get('X-Forwarded-For') or request.remote_addr or '').split(',')[0].strip()

def compute_trust(u):
    c = get_db()
    r = c.execute("SELECT kyc_status FROM users WHERE username=?", (u,)).fetchone()
    if not r: c.close(); return 100
    s = 100
    if r['kyc_status'] == 'APPROVED': s += 200
    d = c.execute("SELECT COUNT(*) as n FROM escrows WHERE seller=? AND status='RELEASED'", (u,)).fetchone()['n']
    s += min(d*5, 300)
    c.close()
    return max(0, min(1000, s))



# ============================================================
#                    Helpers: Ledger + Audit + Points
# ============================================================
def ledger_add(username, debit=0.0, credit=0.0, ref_type='', ref_id='', description=''):
    """إضافة قيد محاسبي - Debit أو Credit"""
    try:
        c = get_db()
        cur = c.cursor()
        p = '%s' if USE_POSTGRES else '?'
        # احصل على الرصيد الحالي
        row = cur.execute(f"SELECT balance FROM users WHERE username={p}", (username,)).fetchone()
        if not row: c.close(); return False
        bal_after = row['balance']
        cur.execute(f"INSERT INTO ledger (username, debit, credit, balance_after, ref_type, ref_id, description) VALUES ({p},{p},{p},{p},{p},{p},{p})",
                   (username, debit, credit, bal_after, ref_type, ref_id, description))
        c.commit()
        c.close()
        return True
    except Exception as e:
        print(f'[LEDGER] {e}')
        return False


def audit(admin, action, target='', details=''):
    """تسجيل عملية إدارية"""
    try:
        c = get_db()
        cur = c.cursor()
        p = '%s' if USE_POSTGRES else '?'
        ip = client_ip() if request else 'N/A'
        cur.execute(f"INSERT INTO audit_log (admin, action, target, details, ip) VALUES ({p},{p},{p},{p},{p})",
                   (admin, action, target, details, ip))
        c.commit()
        c.close()
    except Exception as e:
        print(f'[AUDIT] {e}')


def add_points(username, points):
    """إضافة نقاط للمستخدم"""
    try:
        c = get_db()
        cur = c.cursor()
        p = '%s' if USE_POSTGRES else '?'
        exists = cur.execute(f"SELECT points FROM user_points WHERE username={p}", (username,)).fetchone()
        if exists:
            cur.execute(f"UPDATE user_points SET points=points+{p}, updated_at=CURRENT_TIMESTAMP WHERE username={p}", (points, username))
        else:
            cur.execute(f"INSERT INTO user_points (username, points) VALUES ({p},{p})", (username, points))
        c.commit()
        c.close()
    except Exception as e:
        print(f'[POINTS] {e}')



# ============================================================
#                    AI Agent (Groq / OpenAI)
# ============================================================
def ai_call(messages, max_tokens=500):
    """استدعاء API للذكاء الاصطناعي (Groq أو OpenAI)"""
    if not AI_API_KEY:
        return None
    
    import urllib.request as _ur
    import json as _j
    
    if AI_PROVIDER == 'groq':
        url = 'https://api.groq.com/openai/v1/chat/completions'
    else:
        url = 'https://api.openai.com/v1/chat/completions'
    
    try:
        payload = _j.dumps({
            'model': AI_MODEL,
            'messages': messages,
            'max_tokens': max_tokens,
            'temperature': 0.7
        }).encode()
        
        req = _ur.Request(url, data=payload, headers={
            'Authorization': f'Bearer {AI_API_KEY}',
            'Content-Type': 'application/json'
        })
        
        with _ur.urlopen(req, timeout=20) as resp:
            r = _j.loads(resp.read())
            return r['choices'][0]['message']['content'].strip()
    except Exception as e:
        print(f'[AI-ERR] {e}')
        return None


def ai_build_context(username):
    """بناء سياق للمستخدم ليعرفه AI"""
    try:
        c = get_db()
        p = '%s' if USE_POSTGRES else '?'
        u = c.execute(f"SELECT username, balance, role, kyc_status, trust_score FROM users WHERE username={p}", (username,)).fetchone()
        if not u:
            c.close()
            return 'المستخدم غير مسجل.'
        # صفقاته
        escrows = c.execute(f"SELECT id, amount, status, seller, buyer FROM escrows WHERE seller={p} OR buyer={p} ORDER BY id DESC LIMIT 5", (username, username)).fetchall()
        escrows_txt = '\n'.join([f"  - صفقة #{e['id']}: {e['amount']}$ ({e['status']})" for e in escrows]) or '  لا توجد صفقات.'
        # نزاعات
        disputes = c.execute("SELECT COUNT(*) as n FROM escrows WHERE status='DISPUTED'").fetchone()['n']
        # عدد المستخدمين
        users_count = c.execute("SELECT COUNT(*) as n FROM users").fetchone()['n']
        c.close()
        
        return f"""معلومات المستخدم الحالي:
- الاسم: {u['username']}
- الرصيد: {u['balance']:.2f}$
- الدور: {u['role']}
- حالة KYC: {u['kyc_status']}
- نقاط الثقة: {u['trust_score']}/1000

آخر صفقاته:
{escrows_txt}

معلومات عامة:
- عدد المستخدمين: {users_count}
- النزاعات المفتوحة: {disputes}
- الحد الأقصى للصفقة: 10,000$
- الحد اليومي: 50,000$
- عمولة المنصة: 2%
- التحرير التلقائي: 7 أيام
- التحرير: بواسطة المشتري فقط
"""
    except Exception as e:
        return f'خطأ في السياق: {e}'

def csrf_ok():
    if request.method in ('GET', 'HEAD', 'OPTIONS'): return True
    if request.path in ('/api/login', '/api/register', '/api/ai/engine', '/api/reset_owner', '/api/debug', '/api/owner/login', '/api/owner/change-password', '/api/owner/change-pin', '/api/vault/unlock'): return True
    token = request.headers.get('X-CSRF-Token') or (request.get_json(silent=True) or {}).get('_csrf')
    return token and session.get('_csrf_token') and secrets.compare_digest(token, session['_csrf_token'])

def cleanup():
    global last_cleanup
    if time.time() - last_cleanup < 3600: return
    last_cleanup = time.time()
    now = time.time()
    for s in (login_attempts, register_attempts):
        for k in list(s.keys()):
            s[k] = [t for t in s[k] if now - t < 3600]
            if not s[k]: del s[k]
    try:
        c = get_db(); c.execute("DELETE FROM logs WHERE timestamp < datetime('now','-30 days')"); c.close()
    except: pass

@app.before_request
def _before():
    # ⚠️ تم تعطيل الحماية مؤقتاً لحل مشكلة تسجيل الدخول
    # سنعيدها بشكل صحيح لاحقاً
    ip = threat.get_ip(request)
    
    # 0. القفل التلقائي - معطّل
    if False and threat.is_lockdown() and request.path not in ('/health',):
        return "<h1 style='font-family:Tahoma;text-align:center;color:#f87171;padding:50px'>🚨 المنصة في وضع الإغلاق الأمني المؤقت</h1>", 503
    
    # 1. حظر IP (معطّل افتراضياً)
    if THREAT_DETECTOR_ENABLED and session.get('user') != MASTER_OWNER and threat.is_banned(ip):
        return jsonify({'status': 'ERROR', 'message': 'Access denied'}), 403
    
    # 2. فحص أنماط الهجوم - معطّل مؤقتاً
    if THREAT_DETECTOR_ENABLED:
        threat_check = threat.check_payload(request)
        if threat_check:
            threat.track_attempt(ip, 'injection')
            log_event(f"THREAT_{threat_check['threat']}", ip)
            return jsonify({'status': 'ERROR', 'message': 'Blocked'}), 403
    
    # 3. فحص الملفات الحساسة - معطّل مؤقتاً
    if THREAT_DETECTOR_ENABLED:
        suspicious_paths = ('/.env', '/.git', '/.ssh', '/wp-admin', '/phpmyadmin')
        if any(request.path.startswith(p) for p in suspicious_paths):
            threat.track_attempt(ip, 'scan')
            log_event('PATH_SCAN', ip)
            return jsonify({'status': 'ERROR', 'message': 'Forbidden'}), 403
    
    cleanup()
    if request.method == 'POST':
        if not csrf_ok():
            threat.track_attempt(ip, 'csrf_fail')
            return jsonify({'status': 'ERROR', 'message': 'CSRF'}), 403

@app.after_request
def _after(r):
    r.headers['X-Content-Type-Options'] = 'nosniff'
    r.headers['X-Frame-Options'] = 'DENY'
    r.headers['Referrer-Policy'] = 'no-referrer'
    r.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    return r

# ============ Email + Telegram ============
def send_telegram(msg):
    if not TG_TOKEN or not TG_CHAT: return False
    try:
        import urllib.request as _ur, json as _j
        url = f'https://api.telegram.org/bot{TG_TOKEN}/sendMessage'
        data = _j.dumps({'chat_id': TG_CHAT, 'text': msg, 'parse_mode': 'HTML'}).encode()
        req = _ur.Request(url, data=data, headers={'Content-Type': 'application/json'})
        _ur.urlopen(req, timeout=5); return True
    except Exception as e:
        print(f'[TG] {e}'); return False

def send_email(to, subj, html):
    body = f'''<html><body style="font-family:Tahoma;background:#f3f4f6;padding:20px;direction:rtl">
    <div style="max-width:500px;margin:auto;background:#fff;padding:25px;border-radius:12px;border:2px solid #0284c7">
    <h2 style="color:#0284c7;text-align:center">منصة الضمان المالي</h2><hr>
    {html}<hr><p style="color:#6b7280;font-size:11px;text-align:center">(c) EssamElkomy369</p>
    </div></body></html>'''
    
    # 1. Resend (يعمل على Render)
    if RESEND_API_KEY:
        try:
            import urllib.request as _ur, json as _j
            data = _j.dumps({
                'from': RESEND_FROM,
                'to': [to],
                'subject': subj,
                'html': body
            }).encode()
            req = _ur.Request('https://api.resend.com/emails', data=data, headers={
                'Authorization': f'Bearer {RESEND_API_KEY}',
                'Content-Type': 'application/json'
            })
            with _ur.urlopen(req, timeout=15) as resp:
                r = _j.loads(resp.read())
                print(f'[RESEND] sent to {to}: {r.get("id", "ok")}')
                return True
        except Exception as e:
            print(f'[RESEND] {e}')
    
    # 2. SMTP (يعمل محلياً فقط)
    if GMAIL_USER and GMAIL_PASS:
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            m = MIMEMultipart('alternative')
            m['Subject'] = subj
            m['From'] = f'منصة الضمان <{GMAIL_USER}>'
            m['To'] = to
            m.attach(MIMEText(body, 'html', 'utf-8'))
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, timeout=15) as s:
                s.login(GMAIL_USER, GMAIL_PASS)
                s.send_message(m)
            print(f'[SMTP] sent to {to}')
            return True
        except Exception as e:
            print(f'[SMTP] {e}')
    
    return False

def send_email_to_user(u, subj, html):
    try:
        c = get_db()
        r = c.execute("SELECT email FROM users WHERE username=?", (u,)).fetchone()
        c.close()
        if r and r['email']: return send_email(r['email'], subj, html)
    except: pass
    return False

# ============ AUTH ============
@app.route('/api/register', methods=['POST'])
def api_register():
    d = request.get_json(silent=True) or {}
    u = (d.get('username') or '').strip()
    p = d.get('password') or ''
    ip = client_ip()
    if ip_banned(ip): return jsonify({'status':'ERROR','message':'محظور'})
    if not check_limit(register_attempts, f'r_{ip}', 5, 3600):
        return jsonify({'status':'ERROR','message':'محاولات كثيرة'})
    if not valid_user(u): return jsonify({'status':'ERROR','message':'اسم غير صالح'})
    ok, msg = valid_pass(p)
    if not ok: return jsonify({'status':'ERROR','message':msg})
    c = get_db()
    try:
        c.execute('BEGIN IMMEDIATE')
        ref = secrets.token_hex(4).upper()
        c.execute("INSERT INTO users (username, password_hash, balance, referral_code) VALUES (?,?,?,?)",
                 (u, generate_password_hash(p), 500.0, ref))
        c.execute("INSERT INTO transactions (username, type, amount, note) VALUES (?,?,?,?)",
                 (u, 'BONUS', 500.0, 'رصيد ترحيبي'))
        c.execute('COMMIT')
        log_event('REGISTER', u)
        return jsonify({'status':'SUCCESS','message':f'تم! كود الإحالة: {ref}'})
    except Exception:
        if c.in_transaction: c.execute('ROLLBACK')
        return jsonify({'status':'ERROR','message':'الاسم مستخدم'})
    finally: c.close()

@app.route('/api/login', methods=['POST'])
def api_login():
    d = request.get_json(silent=True) or {}
    u = (d.get('username') or '').strip()
    p = d.get('password') or ''
    ip = client_ip()
    if ip_banned(ip): return jsonify({'status':'ERROR','message':'IP محظور'})
    if not check_limit(login_attempts, f'l_{ip}', 10, 300):
        log_event('RATE_LIMIT', u)
        return jsonify({'status':'ERROR','message':'محاولات كثيرة'})
    c = get_db()
    r = c.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
    c.close()
    if r and check_password_hash(r['password_hash'], p):
        if r['status'] == 'BANNED':
            log_event('BANNED_LOGIN', u)
            return jsonify({'status':'ERROR','message':'محظور'})
        session.clear(); session.permanent = True
        session['user'] = u
        session['user_id'] = r['id']
        session['role'] = r['role']
        session['_csrf_token'] = secrets.token_hex(32)
        log_event('LOGIN', u)
        return jsonify({'status':'SUCCESS','balance':r['balance'],'role':r['role'],'csrf_token':session['_csrf_token']})
    if not check_limit(login_attempts, f'f_{ip}', 15, 300):
        ban_ip(ip, 30)
        return jsonify({'status':'ERROR','message':'IP محظور 30 دقيقة'})
    log_event('FAILED_LOGIN', u)
    return jsonify({'status':'ERROR','message':'بيانات خاطئة'})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'status':'SUCCESS'})

@app.route('/api/me', methods=['GET'])
@login_required
def api_me():
    c = get_db()
    r = c.execute("SELECT username, balance, role, kyc_status, referral_code, trust_score, email FROM users WHERE id=?",
                 (session['user_id'],)).fetchone()
    c.close()
    return jsonify({'status':'SUCCESS','user':dict(r)})

@app.route('/api/change-password', methods=['POST'])
@login_required
def api_change_pwd():
    d = request.get_json(silent=True) or {}
    ok, msg = valid_pass(d.get('new',''))
    if not ok: return jsonify({'status':'ERROR','message':msg})
    c = get_db()
    r = c.execute("SELECT password_hash FROM users WHERE id=?", (session['user_id'],)).fetchone()
    if not r or not check_password_hash(r['password_hash'], d.get('old','')):
        c.close(); return jsonify({'status':'ERROR','message':'كلمة المرور الحالية خاطئة'})
    c.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(d['new']), session['user_id']))
    c.close()
    return jsonify({'status':'SUCCESS','message':'تم التغيير'})

# ============ ESCROW ============
@app.route('/api/escrows', methods=['GET'])
def api_escrows():
    try: off = max(0, int(request.args.get('offset',0)))
    except: off = 0
    c = get_db()
    rows = c.execute("SELECT * FROM escrows ORDER BY id DESC LIMIT 20 OFFSET ?", (off,)).fetchall()
    c.close()
    return jsonify({'escrows':[dict(r) for r in rows]})

@app.route('/api/escrow/create', methods=['POST'])
@login_required
def api_escrow_create():
    d = request.get_json(silent=True) or {}
    seller = (d.get('seller') or '').strip()
    try: amount = round(float(d.get('amount', 0)), 2)
    except: return jsonify({'status':'ERROR','message':'مبلغ غير صالح'})
    buyer = session['user']
    if not seller or amount <= 0: return jsonify({'status':'ERROR','message':'بيانات ناقصة'})
    if buyer == seller: return jsonify({'status':'ERROR','message':'لا صفقة مع نفسك'})
    if amount > MAX_ESCROW: return jsonify({'status':'ERROR','message':f'الحد {MAX_ESCROW}$'})
    with db_lock:
        c = get_db(); cur = c.cursor()
        try:
            cur.execute('BEGIN IMMEDIATE')
            b = cur.execute("SELECT balance, status FROM users WHERE username=?", (buyer,)).fetchone()
            if not b or b['status'] != 'ACTIVE':
                cur.execute('ROLLBACK'); return jsonify({'status':'ERROR','message':'حسابك غير نشط'})
            if b['balance'] < amount:
                cur.execute('ROLLBACK'); return jsonify({'status':'ERROR','message':'رصيدك لا يكفي'})
            if not cur.execute("SELECT 1 FROM users WHERE username=?", (seller,)).fetchone():
                cur.execute('ROLLBACK'); return jsonify({'status':'ERROR','message':'البائع غير موجود'})
            # حد الصفقة الأقصى
            if amount > 10000.0:
                cur.execute('ROLLBACK'); return jsonify({'status':'ERROR','message':'الحد الأقصى 10000$'})
            # حد الصفقات النشطة
            active = cur.execute("SELECT COUNT(*) as n FROM escrows WHERE buyer=%s AND status IN ('LOCKED_SECURE','DISPUTED')", (buyer,)).fetchone()['n']
            if active >= 10:
                cur.execute('ROLLBACK'); return jsonify({'status':'ERROR','message':'الحد الأقصى 10 صفقات نشطة'})
            # الحد اليومي
            today = cur.execute("SELECT COALESCE(SUM(amount),0) as s FROM transactions WHERE username=%s AND type='ESCROW_LOCK' AND DATE(timestamp)=CURRENT_DATE", (buyer,)).fetchone()['s']
            if today + amount > 50000.0:
                cur.execute('ROLLBACK'); return jsonify({'status':'ERROR','message':'تجاوزت الحد اليومي 50000$'})
            cnt = cur.execute("SELECT COUNT(*) as n FROM escrows WHERE buyer=? AND status IN ('LOCKED_SECURE','PENDING','DISPUTED')", (buyer,)).fetchone()['n']
            if cnt >= MAX_ACTIVE:
                cur.execute('ROLLBACK'); return jsonify({'status':'ERROR','message':f'الحد {MAX_ACTIVE} صفقات'})
            cur.execute("SELECT COALESCE(SUM(amount),0) as s FROM transactions WHERE username=? AND type='ESCROW_LOCK' AND DATE(timestamp)=DATE('now')", (buyer,))
            if cur.fetchone()['s'] + amount > DAILY_LIMIT:
                cur.execute('ROLLBACK'); return jsonify({'status':'ERROR','message':f'الحد اليومي {DAILY_LIMIT}$'})
            cur.execute("UPDATE users SET balance=balance-? WHERE username=?", (amount, buyer))
            cur.execute("INSERT INTO escrows (seller, buyer, amount, status) VALUES (?,?,?,'LOCKED_SECURE')", (seller, buyer, amount))
            eid = cur.lastrowid
            cur.execute("INSERT INTO transactions (username, type, amount, note) VALUES (?,?,?,?)",
                       (buyer, 'ESCROW_LOCK', -amount, f'قفل #{eid}'))
            cur.execute("UPDATE treasury SET total_locked=total_locked+? WHERE id=1", (amount,))
            cur.execute('COMMIT')
            notify(seller, '🔔 صفقة جديدة', f'#{eid} بمبلغ {amount}$')
            return jsonify({'status':'SUCCESS','message':f'تم إنشاء #{eid}'})
        except Exception as e:
            if c.in_transaction: cur.execute('ROLLBACK')
            return jsonify({'status':'ERROR','message':str(e)})
        finally: c.close()

@app.route('/api/escrow/release', methods=['POST'])
@login_required
def api_escrow_release():
    d = request.get_json(silent=True) or {}
    try: eid = int(d.get('escrow_id'))
    except: return jsonify({'status':'ERROR','message':'رقم غير صالح'})
    with db_lock:
        c = get_db(); cur = c.cursor()
        try:
            cur.execute('BEGIN IMMEDIATE')
            e = cur.execute("SELECT * FROM escrows WHERE id=? AND status='LOCKED_SECURE'", (eid,)).fetchone()
            if not e:
                cur.execute('ROLLBACK'); return jsonify({'status':'ERROR','message':'غير متاحة'})
            if e['buyer'] != session['user']:
                cur.execute('ROLLBACK'); return jsonify({'status':'ERROR','message':'المشتري فقط'})
            rate = cur.execute("SELECT commission_rate FROM treasury WHERE id=1").fetchone()['commission_rate']
            comm = round(e['amount'] * rate / 100.0, 2)
            net = round(e['amount'] - comm, 2)
            cur.execute("UPDATE users SET balance=balance+?, successful_deals=successful_deals+1 WHERE username=?", (net, e['seller']))
            cur.execute("UPDATE escrows SET status='RELEASED', updated_at=CURRENT_TIMESTAMP WHERE id=?", (eid,))
            cur.execute("UPDATE treasury SET balance=balance+?, total_commission=total_commission+?, total_locked=total_locked-?, total_released=total_released+? WHERE id=1",
                       (comm, comm, e['amount'], e['amount']))
            cur.execute("INSERT INTO transactions (username, type, amount, note) VALUES (?,?,?,?)",
                       (e['seller'], 'RELEASE', net, f'#{eid} (عمولة {comm}$)'))
            cur.execute("INSERT INTO transactions (username, type, amount, note) VALUES (?,?,?,?)",
                       ('__TREASURY__', 'COMMISSION', comm, f'عمولة #{eid}'))
            cur.execute('COMMIT')
            notify(e['seller'], '💰 تحرير', f'استلمت {net}$ لصفقة #{eid}')
            return jsonify({'status':'SUCCESS','message':f'تم تحرير {net}$ (عمولة {comm}$)'})
        except Exception as ex:
            if c.in_transaction: cur.execute('ROLLBACK')
            return jsonify({'status':'ERROR','message':str(ex)})
        finally: c.close()

@app.route('/api/escrow/dispute', methods=['POST'])
@login_required
def api_escrow_dispute():
    d = request.get_json(silent=True) or {}
    try: eid = int(d.get('escrow_id'))
    except: return jsonify({'status':'ERROR','message':'رقم غير صالح'})
    reason = (d.get('reason') or '').strip()[:500]
    if not reason: return jsonify({'status':'ERROR','message':'سبب النزاع مطلوب'})
    u = session['user']
    c = get_db(); cur = c.cursor()
    try:
        cur.execute('BEGIN IMMEDIATE')
        e = cur.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
        if not e or u not in (e['seller'], e['buyer']):
            cur.execute('ROLLBACK'); return jsonify({'status':'ERROR','message':'غير مخول'})
        if e['status'] != 'LOCKED_SECURE':
            cur.execute('ROLLBACK'); return jsonify({'status':'ERROR','message':'غير قابلة'})
        cur.execute("UPDATE escrows SET status='DISPUTED', dispute_reason=? WHERE id=?", (reason, eid))
        cur.execute('COMMIT')
        notify(MASTER_OWNER, '🚨 نزاع', f'#{eid}')
        return jsonify({'status':'SUCCESS','message':'تم فتح النزاع'})
    except Exception as ex:
        if c.in_transaction: cur.execute('ROLLBACK')
        return jsonify({'status':'ERROR','message':str(ex)})
    finally: c.close()

# ============ WALLET ============
@app.route('/api/wallet/deposit', methods=['POST'])
@login_required
def api_deposit():
    try: a = round(float((request.get_json(silent=True) or {}).get('amount',0)), 2)
    except: return jsonify({'status':'ERROR','message':'مبلغ غير صالح'})
    if a <= 0 or a > 10000: return jsonify({'status':'ERROR','message':'1-10000'})
    with db_lock:
        c = get_db()
        c.execute('BEGIN IMMEDIATE')
        c.execute("UPDATE users SET balance=balance+? WHERE id=?", (a, session['user_id']))
        c.execute("INSERT INTO transactions (username, type, amount, note) VALUES (?,?,?,?)",
                 (session['user'], 'DEPOSIT', a, 'إيداع'))
        c.commit(); c.close()
    return jsonify({'status':'SUCCESS','message':f'تم إيداع {a}$'})

@app.route('/api/wallet/withdraw', methods=['POST'])
@login_required
def api_withdraw():
    try: a = round(float((request.get_json(silent=True) or {}).get('amount',0)), 2)
    except: return jsonify({'status':'ERROR','message':'مبلغ غير صالح'})
    if a <= 0: return jsonify({'status':'ERROR','message':'مبلغ غير صالح'})
    with db_lock:
        c = get_db()
        c.execute('BEGIN IMMEDIATE')
        u = c.execute("SELECT balance FROM users WHERE id=?", (session['user_id'],)).fetchone()
        if u['balance'] < a:
            c.execute('ROLLBACK'); c.close()
            return jsonify({'status':'ERROR','message':'رصيدك لا يكفي'})
        c.execute("UPDATE users SET balance=balance-? WHERE id=?", (a, session['user_id']))
        c.execute("INSERT INTO transactions (username, type, amount, note) VALUES (?,?,?,?)",
                 (session['user'], 'WITHDRAW', -a, 'سحب'))
        c.commit(); c.close()
    return jsonify({'status':'SUCCESS','message':f'تم سحب {a}$'})

@app.route('/api/transactions', methods=['GET'])
@login_required
def api_txs():
    c = get_db()
    rows = c.execute("SELECT * FROM transactions WHERE username=? ORDER BY id DESC LIMIT 30", (session['user'],)).fetchall()
    c.close()
    return jsonify({'status':'SUCCESS','transactions':[dict(r) for r in rows]})

# ============ ADMIN ============
@app.route('/api/admin/ban', methods=['POST'])
@login_required
def api_ban():
    if not is_admin(): return jsonify({'status':'ERROR','message':'مرفوض'})
    t = (request.get_json(silent=True) or {}).get('target','').strip()
    if t == MASTER_OWNER: return jsonify({'status':'ERROR','message':'لا يمكن حظر المالك'})
    c = get_db()
    c.execute("UPDATE users SET status='BANNED' WHERE username=?", (t,))
    c.close()
    log_event(f'BAN_{t}', session['user'])
    return jsonify({'status':'SUCCESS','message':f'تم حظر {t}'})

@app.route('/api/admin/unban', methods=['POST'])
@login_required
def api_unban():
    if not is_admin(): return jsonify({'status':'ERROR','message':'مرفوض'})
    t = (request.get_json(silent=True) or {}).get('target','').strip()
    c = get_db()
    c.execute("UPDATE users SET status='ACTIVE' WHERE username=?", (t,))
    c.close()
    return jsonify({'status':'SUCCESS','message':f'تم رفع الحظر'})

@app.route('/api/admin/refund', methods=['POST'])
@login_required
def api_admin_refund():
    if not is_admin(): return jsonify({'status':'ERROR','message':'مرفوض'})
    try: eid = int((request.get_json(silent=True) or {}).get('escrow_id'))
    except: return jsonify({'status':'ERROR','message':'رقم غير صالح'})
    with db_lock:
        c = get_db(); cur = c.cursor()
        try:
            cur.execute('BEGIN IMMEDIATE')
            e = cur.execute("SELECT * FROM escrows WHERE id=? AND status IN ('DISPUTED','LOCKED_SECURE')", (eid,)).fetchone()
            if not e:
                cur.execute('ROLLBACK'); return jsonify({'status':'ERROR','message':'غير قابلة'})
            cur.execute("UPDATE users SET balance=balance+? WHERE username=?", (e['amount'], e['buyer']))
            cur.execute("UPDATE escrows SET status='REFUNDED' WHERE id=?", (eid,))
            cur.execute("UPDATE treasury SET total_locked=total_locked-?, total_refunded=total_refunded+? WHERE id=1", (e['amount'], e['amount']))
            cur.execute("INSERT INTO transactions (username, type, amount, note) VALUES (?,?,?,?)",
                       (e['buyer'], 'REFUND', e['amount'], f'استرداد #{eid}'))
            cur.execute('COMMIT')
            notify(e['buyer'], '✅ استرداد', f'تم استرداد {e["amount"]}$')
            return jsonify({'status':'SUCCESS','message':'تم الاسترداد'})
        except Exception as ex:
            if c.in_transaction: cur.execute('ROLLBACK')
            return jsonify({'status':'ERROR','message':str(ex)})
        finally: c.close()

@app.route('/api/admin/stats', methods=['GET'])
@login_required
def api_stats():
    if not is_admin(): return jsonify({'status':'ERROR','message':'مرفوض'})
    c = get_db()
    u = c.execute("SELECT COUNT(*) as n FROM users").fetchone()['n']
    e = c.execute("SELECT COUNT(*) as n FROM escrows").fetchone()['n']
    d = c.execute("SELECT COUNT(*) as n FROM escrows WHERE status='DISPUTED'").fetchone()['n']
    t = c.execute("SELECT * FROM treasury WHERE id=1").fetchone()
    c.close()
    return jsonify({'status':'SUCCESS','users':u,'escrows':e,'disputes':d,
                    'balance':t['balance'],'commission':t['total_commission']})

@app.route('/api/admin/users', methods=['GET'])
@login_required
def api_users():
    if not is_admin(): return jsonify({'status':'ERROR','message':'مرفوض'})
    c = get_db()
    rows = c.execute("SELECT username, role, status, balance, kyc_status FROM users ORDER BY id DESC LIMIT 100").fetchall()
    c.close()
    return jsonify({'status':'SUCCESS','users':[dict(r) for r in rows]})


# ============ MILESTONES ============
@app.route('/escrow/<int:eid>/milestones', methods=['GET'])
@login_required
def ms_list(eid):
    c = get_db()
    e = c.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
    if not e or session['user'] not in (e['seller'], e['buyer']):
        c.close(); return jsonify({'status':'ERROR','message':'غير مخول'})
    rows = c.execute("SELECT * FROM milestones WHERE escrow_id=? ORDER BY order_num", (eid,)).fetchall()
    c.close()
    return jsonify({'status':'SUCCESS','milestones':[dict(r) for r in rows]})

@app.route('/escrow/<int:eid>/milestone/add', methods=['POST'])
@login_required
def ms_add(eid):
    d = request.get_json(silent=True) or {}
    title = (d.get('title') or '').strip()[:100]
    try: amount = round(float(d.get('amount', 0)), 2)
    except: return jsonify({'status':'ERROR','message':'مبلغ غير صالح'})
    if not title or amount <= 0: return jsonify({'status':'ERROR','message':'بيانات ناقصة'})
    c = get_db()
    e = c.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
    if not e or e['seller'] != session['user'] or e['status'] != 'LOCKED_SECURE':
        c.close(); return jsonify({'status':'ERROR','message':'غير مخول'})
    total = c.execute("SELECT COALESCE(SUM(amount),0) as s FROM milestones WHERE escrow_id=?", (eid,)).fetchone()['s']
    if total + amount > e['amount']:
        c.close(); return jsonify({'status':'ERROR','message':f'يتجاوز {e["amount"]}$'})
    order = c.execute("SELECT COALESCE(MAX(order_num),0)+1 as n FROM milestones WHERE escrow_id=?", (eid,)).fetchone()['n']
    c.execute("INSERT INTO milestones (escrow_id, title, amount, order_num) VALUES (?,?,?,?)",
             (eid, title, amount, order))
    c.commit(); c.close()
    notify(e['buyer'], '📋 مرحلة جديدة', f'{title} لصفقة #{eid}')
    return jsonify({'status':'SUCCESS','message':'تمت الإضافة'})

@app.route('/milestone/<int:mid>/release', methods=['POST'])
@login_required
def ms_release(mid):
    with db_lock:
        c = get_db(); cur = c.cursor()
        try:
            cur.execute('BEGIN IMMEDIATE')
            m = cur.execute("SELECT * FROM milestones WHERE id=? AND status='PENDING'", (mid,)).fetchone()
            if not m:
                cur.execute('ROLLBACK'); return jsonify({'status':'ERROR','message':'غير متاحة'})
            e = cur.execute("SELECT * FROM escrows WHERE id=?", (m['escrow_id'],)).fetchone()
            if not e or e['buyer'] != session['user']:
                cur.execute('ROLLBACK'); return jsonify({'status':'ERROR','message':'المشتري فقط'})
            if e['status'] != 'LOCKED_SECURE':
                cur.execute('ROLLBACK'); return jsonify({'status':'ERROR','message':'الصفقة غير نشطة'})
            rate = cur.execute("SELECT commission_rate FROM treasury WHERE id=1").fetchone()['commission_rate']
            comm = round(m['amount'] * rate / 100.0, 2)
            net = round(m['amount'] - comm, 2)
            cur.execute("UPDATE users SET balance=balance+? WHERE username=?", (net, e['seller']))
            cur.execute("UPDATE milestones SET status='RELEASED' WHERE id=?", (mid,))
            cur.execute("UPDATE escrows SET status='IN_PROGRESS' WHERE id=?", (e['id'],))
            cur.execute("UPDATE treasury SET balance=balance+?, total_commission=total_commission+? WHERE id=1", (comm, comm))
            cur.execute("INSERT INTO transactions (username, type, amount, note) VALUES (?,?,?,?)",
                       (e['seller'], 'MILESTONE', net, f'مرحلة #{mid}'))
            cur.execute('COMMIT')
            notify(e['seller'], '💰 مرحلة محررة', f'{net}$ لـ {m["title"]}')
            return jsonify({'status':'SUCCESS','message':f'تم تحرير {net}$'})
        except Exception as ex:
            if c.in_transaction: cur.execute('ROLLBACK')
            return jsonify({'status':'ERROR','message':str(ex)})
        finally: c.close()

# ============ CHAT ============
@app.route('/escrow/<int:eid>/messages', methods=['GET'])
@login_required
def chat_get(eid):
    c = get_db()
    e = c.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
    if not e or session['user'] not in (e['seller'], e['buyer']):
        c.close(); return jsonify({'status':'ERROR','message':'غير مخول'})
    rows = c.execute("SELECT * FROM messages WHERE escrow_id=? ORDER BY id ASC LIMIT 200", (eid,)).fetchall()
    c.close()
    return jsonify({'status':'SUCCESS','messages':[dict(r) for r in rows]})

@app.route('/escrow/<int:eid>/messages', methods=['POST'])
@login_required
def chat_send(eid):
    body = ((request.get_json(silent=True) or {}).get('body') or '').strip()[:1000]
    if not body: return jsonify({'status':'ERROR','message':'رسالة فارغة'})
    c = get_db()
    e = c.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
    if not e or session['user'] not in (e['seller'], e['buyer']):
        c.close(); return jsonify({'status':'ERROR','message':'غير مخول'})
    c.execute("INSERT INTO messages (escrow_id, sender, body) VALUES (?,?,?)", (eid, session['user'], body))
    c.commit(); c.close()
    other = e['seller'] if session['user'] == e['buyer'] else e['buyer']
    notify(other, '💬 رسالة', f'من {session["user"]}')
    return jsonify({'status':'SUCCESS'})

# ============ REVIEWS ============
@app.route('/review/add', methods=['POST'])
@login_required
def review_add():
    d = request.get_json(silent=True) or {}
    try: eid = int(d.get('escrow_id')); rating = int(d.get('rating', 0))
    except: return jsonify({'status':'ERROR','message':'بيانات غير صالحة'})
    if rating < 1 or rating > 5: return jsonify({'status':'ERROR','message':'1-5'})
    comment = (d.get('comment') or '').strip()[:300]
    c = get_db()
    e = c.execute("SELECT * FROM escrows WHERE id=? AND status='RELEASED'", (eid,)).fetchone()
    if not e or session['user'] not in (e['seller'], e['buyer']):
        c.close(); return jsonify({'status':'ERROR','message':'غير مخول'})
    if c.execute("SELECT 1 FROM reviews WHERE escrow_id=? AND reviewer=?", (eid, session['user'])).fetchone():
        c.close(); return jsonify({'status':'ERROR','message':'قيّمت مسبقاً'})
    reviewee = e['seller'] if session['user'] == e['buyer'] else e['buyer']
    c.execute("INSERT INTO reviews (escrow_id, reviewer, reviewee, rating, comment) VALUES (?,?,?,?,?)",
             (eid, session['user'], reviewee, rating, comment))
    c.commit(); c.close()
    notify(reviewee, '⭐ تقييم', f'{rating}/5 من {session["user"]}')
    return jsonify({'status':'SUCCESS','message':'شكراً'})

@app.route('/user/<username>/reviews', methods=['GET'])
def user_reviews(username):
    c = get_db()
    rows = c.execute("SELECT * FROM reviews WHERE reviewee=? ORDER BY id DESC LIMIT 20", (username,)).fetchall()
    avg = c.execute("SELECT AVG(rating) as a, COUNT(*) as n FROM reviews WHERE reviewee=?", (username,)).fetchone()
    c.close()
    return jsonify({'status':'SUCCESS','reviews':[dict(r) for r in rows],
                    'avg':round(avg['a'],2) if avg['a'] else 0,'count':avg['n']})

# ============ EVIDENCE ============
@app.route('/escrow/<int:eid>/evidence/list', methods=['GET'])
@login_required
def ev_list(eid):
    c = get_db()
    e = c.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
    if not e or session['user'] not in (e['seller'], e['buyer']):
        c.close(); return jsonify({'status':'ERROR','message':'غير مخول'})
    rows = c.execute("SELECT * FROM evidence WHERE escrow_id=? ORDER BY id DESC", (eid,)).fetchall()
    c.close()
    return jsonify({'status':'SUCCESS','evidence':[dict(r) for r in rows]})

@app.route('/escrow/<int:eid>/evidence/add', methods=['POST'])
@login_required
def ev_add(eid):
    d = request.get_json(silent=True) or {}
    content = (d.get('content') or '').strip()[:50000]
    note = (d.get('note') or '').strip()[:300]
    if not content: return jsonify({'status':'ERROR','message':'المحتوى مطلوب'})
    c = get_db()
    e = c.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
    if not e or session['user'] not in (e['seller'], e['buyer']):
        c.close(); return jsonify({'status':'ERROR','message':'غير مخول'})
    c.execute("INSERT INTO evidence (escrow_id, uploader, content, note) VALUES (?,?,?,?)",
             (eid, session['user'], content, note))
    c.commit(); c.close()
    other = e['seller'] if session['user'] == e['buyer'] else e['buyer']
    notify(other, '📎 دليل جديد', f'من {session["user"]}')
    return jsonify({'status':'SUCCESS','message':'تم الرفع'})

# ============ KYC ============
@app.route('/api/kyc/submit', methods=['POST'])
@login_required
def api_kyc_submit():
    d = request.get_json(silent=True) or {}
    fn = (d.get('full_name') or '').strip()[:100]
    idn = (d.get('id_number') or '').strip()[:50]
    if not fn or not idn: return jsonify({'status':'ERROR','message':'بيانات ناقصة'})
    c = get_db()
    if c.execute("SELECT 1 FROM kyc_submissions WHERE username=? AND status='PENDING'", (session['user'],)).fetchone():
        c.close(); return jsonify({'status':'ERROR','message':'قيد المراجعة'})
    c.execute("INSERT INTO kyc_submissions (username, full_name, id_number) VALUES (?,?,?)",
             (session['user'], fn, idn))
    c.execute("UPDATE users SET kyc_status='PENDING' WHERE id=?", (session['user_id'],))
    c.commit(); c.close()
    notify(MASTER_OWNER, '📋 KYC جديد', session['user'])
    return jsonify({'status':'SUCCESS','message':'تم الإرسال'})

@app.route('/api/kyc/status', methods=['GET'])
@login_required
def api_kyc_status():
    c = get_db()
    r = c.execute("SELECT * FROM kyc_submissions WHERE username=? ORDER BY id DESC LIMIT 1", (session['user'],)).fetchone()
    c.close()
    return jsonify({'status':'SUCCESS','kyc':dict(r) if r else None})

@app.route('/api/admin/kyc/list', methods=['GET'])
@login_required
def api_kyc_list():
    if not is_admin(): return jsonify({'status':'ERROR','message':'مرفوض'})
    c = get_db()
    rows = c.execute("SELECT * FROM kyc_submissions WHERE status='PENDING' ORDER BY id DESC").fetchall()
    c.close()
    return jsonify({'status':'SUCCESS','submissions':[dict(r) for r in rows]})

@app.route('/api/admin/kyc/review', methods=['POST'])
@login_required
def api_kyc_review():
    if not is_admin(): return jsonify({'status':'ERROR','message':'مرفوض'})
    d = request.get_json(silent=True) or {}
    sid = d.get('id'); dec = d.get('decision')
    if dec not in ('APPROVED','REJECTED'): return jsonify({'status':'ERROR','message':'قرار غير صالح'})
    c = get_db()
    r = c.execute("SELECT * FROM kyc_submissions WHERE id=?", (sid,)).fetchone()
    if not r:
        c.close(); return jsonify({'status':'ERROR','message':'غير موجود'})
    c.execute("UPDATE kyc_submissions SET status=? WHERE id=?", (dec, sid))
    c.execute("UPDATE users SET kyc_status=? WHERE username=?", (dec, r['username']))
    c.commit(); c.close()
    notify(r['username'], '✅ قرار KYC', dec)
    return jsonify({'status':'SUCCESS','message':f'تم {dec}'})

# ============ NOTIFICATIONS ============
@app.route('/api/notifications', methods=['GET'])
@login_required
def api_notifs():
    c = get_db()
    rows = c.execute("SELECT * FROM notifications WHERE username=? ORDER BY id DESC LIMIT 30", (session['user'],)).fetchall()
    unread = c.execute("SELECT COUNT(*) as n FROM notifications WHERE username=? AND is_read=0", (session['user'],)).fetchone()['n']
    c.close()
    return jsonify({'status':'SUCCESS','notifications':[dict(r) for r in rows],'unread':unread})

@app.route('/api/notifications/read', methods=['POST'])
@login_required
def api_notifs_read():
    c = get_db()
    c.execute("UPDATE notifications SET is_read=1 WHERE username=?", (session['user'],))
    c.close()
    return jsonify({'status':'SUCCESS'})

@app.route('/api/save-email', methods=['POST'])
@login_required
def api_save_email():
    d = request.get_json(silent=True) or {}
    email = (d.get('email') or '').strip()[:100]
    if not email or '@' not in email: return jsonify({'status':'ERROR','message':'بريد غير صالح'})
    c = get_db()
    c.execute("UPDATE users SET email=? WHERE id=?", (email, session['user_id']))
    c.close()
    return jsonify({'status':'SUCCESS','message':'تم الحفظ'})

# ============ AI ============

@app.route('/api/export/pdf')
@login_required
def api_export_pdf(): return _pdf_export()

@app.route('/api/export/csv')
@login_required
def api_export_csv():
    c = get_db()
    rows = c.execute("SELECT * FROM transactions WHERE username=? ORDER BY id DESC", (session['user'],)).fetchall()
    c.close()
    out = _io.StringIO()
    w = csv.writer(out)
    w.writerow(['ID','Type','Amount','Note','Timestamp'])
    for r in rows: w.writerow([r['id'], r['type'], r['amount'], r['note'], r['timestamp']])
    out.seek(0)
    return send_file(_io.BytesIO(out.getvalue().encode('utf-8-sig')),
                    mimetype='text/csv', as_attachment=True,
                    download_name=f'statement_{session["user"]}.csv')

# ============ PWA ============
PWA_MANIFEST = {
    'name': 'منصة الضمان المالي الآمن',
    'short_name': 'Escrow',
    'start_url': '/',
    'display': 'standalone',
    'background_color': '#07090e',
    'theme_color': '#0284c7',
    'orientation': 'portrait',
    'lang': 'ar',
    'dir': 'rtl',
    'icons': [{
        'src': 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxOTIgMTkyIj48cmVjdCB3aWR0aD0iMTkyIiBoZWlnaHQ9IjE5MiIgcng9IjMyIiBmaWxsPSIjMDcwOTBlIi8+PHRleHQgeD0iOTYiIHk9IjEyMCIgZm9udC1zaXplPSI5NiIgdGV4dC1hbmNob3I9Im1pZGRsZSI+8J+boO+4jzwvdGV4dD48L3N2Zz4=',
        'sizes': '192x192',
        'type': 'image/svg+xml'
    }]
}

@app.route('/manifest.json')
def pwa_manifest():
    from flask import Response
    import json as _j
    return Response(_j.dumps(PWA_MANIFEST, ensure_ascii=False),
                   mimetype='application/manifest+json')

@app.route('/sw.js')
def pwa_sw():
    from flask import Response
    sw = """
const CACHE = 'escrow-v1';
self.addEventListener('install', e => { self.skipWaiting(); });
self.addEventListener('activate', e => { clients.claim(); });
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
});
"""
    return Response(sw, mimetype='application/javascript')

# ============ DASHBOARD ============
DASHBOARD_HTML = '''<!DOCTYPE html><html lang="ar" dir="rtl"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>📊 لوحة التحليلات</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Tahoma,sans-serif;background:#07090e;color:#f1f5f9;padding:15px}
.c{max-width:1100px;margin:auto;background:#111827;padding:20px;border-radius:12px;border:1px solid #1f2937}
h1{color:#38bdf8;text-align:center;font-size:22px;margin-bottom:20px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.stat{background:#1f2937;padding:15px;border-radius:10px;border:1px solid #374151;text-align:center}
.stat .l{color:#9ca3af;font-size:11px;margin-bottom:5px}
.stat .v{font-size:22px;font-weight:bold;color:#10b981}
.stat.gold .v{color:#fbbf24}.stat.red .v{color:#f87171}.stat.blue .v{color:#38bdf8}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:15px;margin-bottom:15px}
@media(max-width:768px){.charts{grid-template-columns:1fr}}
.chart-box{background:#1f2937;padding:15px;border-radius:10px;border:1px solid #374151;height:300px}
.chart-box h3{color:#cbd5e1;margin-bottom:12px;font-size:14px;border-bottom:1px solid #374151;padding-bottom:8px}
.back{display:block;text-align:center;color:#38bdf8;text-decoration:none;margin-top:15px;font-size:13px;padding:10px;background:#0b0f19;border-radius:8px}
</style></head><body>
<div class="c">
<h1>📊 لوحة التحليلات</h1>
<div class="stats">
<div class="stat blue"><div class="l">👥 المستخدمون</div><div class="v" id="s1">0</div></div>
<div class="stat"><div class="l">📋 الصفقات</div><div class="v" id="s2">0</div></div>
<div class="stat gold"><div class="l">💰 الخزنة</div><div class="v" id="s3">0$</div></div>
<div class="stat gold"><div class="l">📈 العمولات</div><div class="v" id="s4">0$</div></div>
<div class="stat red"><div class="l">⚠️ النزاعات</div><div class="v" id="s5">0</div></div>
<div class="stat"><div class="l">🔒 النشطة</div><div class="v" id="s6">0</div></div>
</div>
<div class="charts">
<div class="chart-box"><h3>📊 حالات الصفقات</h3><canvas id="c1"></canvas></div>
<div class="chart-box"><h3>📈 العمولات (7 أيام)</h3><canvas id="c2"></canvas></div>
</div>
<a href="/" class="back">← العودة</a>
</div>
<script>
fetch('/api/admin/dashboard-data').then(r=>r.json()).then(d=>{
if(d.status!=='SUCCESS'){alert(d.message);return;}
['users','total','balance','comm','disp','locked'].forEach((k,i)=>{
  const el=document.getElementById('s'+(i+1)); if(!el)return;
  const v=d[k==='users'?'users':k==='total'?'total_escrows':k==='balance'?'balance':k==='comm'?'commission':k==='disp'?'disputes':'locked'];
  el.innerText=typeof v==='number'&&(k==='balance'||k==='comm')?v.toFixed(2)+'$':v;
});
new Chart(document.getElementById('c1'),{type:'doughnut',data:{labels:['محررة','مقفلة','نزاع','مستردة','ملغاة'],
datasets:[{data:[d.released,d.locked,d.disputes,d.refunded,d.cancelled],
backgroundColor:['#10b981','#f59e0b','#dc2626','#8b5cf6','#6b7280'],borderColor:'#111827',borderWidth:2}]},
options:{plugins:{legend:{labels:{color:'#cbd5e1'}}},maintainAspectRatio:false}});
new Chart(document.getElementById('c2'),{type:'line',data:{labels:d.days,
datasets:[{label:'العمولات',data:d.commissions_by_day,borderColor:'#fbbf24',backgroundColor:'rgba(251,191,36,0.2)',tension:0.3,fill:true,borderWidth:3}]},
options:{plugins:{legend:{labels:{color:'#cbd5e1'}}},scales:{x:{ticks:{color:'#94a3b8'},grid:{color:'#374151'}},y:{ticks:{color:'#94a3b8'},beginAtZero:true,grid:{color:'#374151'}}},maintainAspectRatio:false}});
});
</script></body></html>'''

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not is_admin():
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>🚫 مرفوض</h1>"
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/admin/dashboard-data', methods=['GET'])
@login_required
def api_admin_dashboard():
    if not is_admin(): return jsonify({'status':'ERROR','message':'مرفوض'})
    c = get_db()
    users = c.execute("SELECT COUNT(*) as n FROM users").fetchone()['n']
    total = c.execute("SELECT COUNT(*) as n FROM escrows").fetchone()['n']
    disputes = c.execute("SELECT COUNT(*) as n FROM escrows WHERE status='DISPUTED'").fetchone()['n']
    locked = c.execute("SELECT COUNT(*) as n FROM escrows WHERE status='LOCKED_SECURE'").fetchone()['n']
    released = c.execute("SELECT COUNT(*) as n FROM escrows WHERE status='RELEASED'").fetchone()['n']
    refunded = c.execute("SELECT COUNT(*) as n FROM escrows WHERE status='REFUNDED'").fetchone()['n']
    cancelled = c.execute("SELECT COUNT(*) as n FROM escrows WHERE status='CANCELLED'").fetchone()['n']
    t = c.execute("SELECT * FROM treasury WHERE id=1").fetchone()
    rows = c.execute("""SELECT DATE(timestamp) as d, COALESCE(SUM(amount),0) as s
        FROM transactions WHERE type IN ('COMMISSION','RELEASE','MILESTONE')
        AND timestamp >= datetime('now','-7 days')
        GROUP BY DATE(timestamp) ORDER BY d""").fetchall()
    days_map = {r['d']: r['s'] for r in rows}
    days, vals = [], []
    from datetime import datetime as _dt, timedelta as _td
    for i in range(6,-1,-1):
        d = (_dt.now()-_td(days=i)).strftime('%Y-%m-%d')
        days.append(d[5:]); vals.append(round(days_map.get(d,0),2))
    c.close()
    return jsonify({'status':'SUCCESS','users':users,'total_escrows':total,
                    'disputes':disputes,'locked':locked,'released':released,
                    'refunded':refunded,'cancelled':cancelled,
                    'balance':t['balance'],'commission':t['total_commission'],
                    'days':days,'commissions_by_day':vals})


# ============ HTML MAIN TEMPLATE ============
HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#0284c7">
<link rel="manifest" href="/manifest.json">
<meta name="apple-mobile-web-app-capable" content="yes">
<title>منصة الضمان المالي الآمن</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,"Segoe UI",Tahoma,sans-serif;background:#07090e;color:#f1f5f9;padding:10px;line-height:1.5;min-height:100vh}
.container{max-width:1000px;margin:auto;background:#111827;padding:15px;border-radius:12px;box-shadow:0 8px 20px rgba(0,0,0,0.7);border:1px solid #1f2937}
.header{text-align:center;border-bottom:1px solid #1f2937;padding-bottom:12px;margin-bottom:15px;position:relative}
.logo{font-size:36px}
h2{color:#38bdf8;font-size:20px;margin:0 0 5px}
.badge{color:#10b981;font-size:12px;background:#064e3b;padding:4px 10px;border-radius:20px;display:inline-block}
.secret{position:absolute;top:5px;left:5px;width:30px;height:30px;background:#b45309;border-radius:50%;cursor:pointer;opacity:1;border:2px solid #fbbf24}
.grid{display:flex;flex-direction:column;gap:15px}
@media(min-width:768px){.grid{display:grid;grid-template-columns:1fr 1fr;gap:15px}}
.section{background:#1f2937;padding:15px;border-radius:10px;border:1px solid #374151}
h3,h4{margin:0 0 12px;color:#cbd5e1;font-size:15px;border-bottom:1px solid #374151;padding-bottom:8px}
.fg{margin-bottom:12px}
label{display:block;font-size:12px;color:#94a3b8;margin-bottom:4px}
input,select,textarea{width:100%;padding:11px;border-radius:8px;background:#0b0f19;color:#fff;border:1px solid #4b5563;font-size:14px;font-family:inherit}
input:focus,select:focus,textarea:focus{border-color:#38bdf8;outline:none}
button{width:100%;padding:11px;border-radius:8px;border:none;font-size:14px;font-weight:bold;cursor:pointer;margin-top:6px;transition:.2s;font-family:inherit}
button:active{transform:scale(.98)}
.bp{background:#0284c7;color:#fff}.bs{background:#10b981;color:#fff}.bd{background:#dc2626;color:#fff}
.bw{background:#d97706;color:#fff}.bg{background:#4b5563;color:#fff}.bgold{background:#b45309;color:#fff}
.row{display:flex;justify-content:space-between;align-items:center;font-size:13px;background:#0b0f19;padding:10px;border-radius:6px;margin-bottom:8px}
.chat{background:#0b0f19;padding:10px;height:200px;overflow-y:scroll;border:1px solid #4b5563;border-radius:6px;margin-bottom:8px;font-size:13px}
.item{background:#0b0f19;padding:12px;margin-top:8px;border-radius:8px;border-right:4px solid #10b981;font-size:13px}
.item.locked{border-right-color:#f59e0b}.item.disputed{border-right-color:#dc2626}
.item.released{opacity:.7}.item.refunded{border-right-color:#8b5cf6;opacity:.7}
.admin{background:#3d1a05;border:1px solid #b45309;display:none}
.ok{color:#4ade80;font-size:12px;margin-top:6px}.err{color:#f87171;font-size:12px;margin-top:6px}
.hide{display:none!important}
.tabs{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:12px;border-bottom:1px solid #374151;padding-bottom:8px}
.tab{padding:8px 12px;background:#0b0f19;border:1px solid #374151;border-radius:6px;cursor:pointer;font-size:12px;color:#94a3b8}
.tab.on{background:#0284c7;color:#fff;border-color:#0284c7}
#toasts{position:fixed;top:15px;left:50%;transform:translateX(-50%);z-index:9999;width:90%;max-width:400px}
.toast{padding:12px 16px;border-radius:8px;margin-bottom:8px;color:#fff;font-weight:bold;font-size:13px;box-shadow:0 4px 12px rgba(0,0,0,.5)}
.toast.s{background:#10b981}.toast.e{background:#dc2626}.toast.i{background:#0284c7}
table{width:100%;border-collapse:collapse;font-size:12px;margin-top:8px}
th,td{padding:6px;text-align:right;border-bottom:1px solid #1f2937}
th{color:#9ca3af;background:#0b0f19}
.modal{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.85);z-index:9998;padding:15px;overflow-y:auto;display:none}
.modal.on{display:block}
.modal-c{max-width:600px;margin:30px auto;background:#111827;padding:20px;border-radius:12px;border:1px solid #374151}
</style>
</head>
<body>
<div id="toasts"></div>
<div class="container">
<div class="header">
<div class="logo">🛡️</div>
<h2>منصة الضمان المالي الآمن</h2>
<div class="badge">Enterprise Escrow • EssamElkomy369</div>
<div class="secret" onclick="location.href='/owner'" title=""></div>
</div>

<!-- Auth View -->
<div id="authView" class="grid">
<div class="section">
<h3>👤 دخول / حساب جديد</h3>
<div class="fg"><label>اسم المستخدم</label><input id="u" placeholder="3-30 حرف/رقم"></div>
<div class="fg"><label>كلمة المرور</label><input type="password" id="p" placeholder="8+ أحرف ورقم"></div>
<button class="bp" onclick="reg()">تسجيل حساب جديد</button>
<button class="bs" onclick="login()">تسجيل الدخول</button>
</div>
<div class="section">
<h3>💰 محفظتك</h3>
<div class="row"><span>المستخدم:</span><b id="who" style="color:#38bdf8">غير مسجل</b></div>
<div class="row"><span>الرصيد:</span><b id="bal" style="color:#10b981">0.00 $</b></div>
<div class="row"><span>⭐ الثقة:</span><b id="trust" style="color:#fbbf24">--</b></div>
</div>
</div>

<!-- Main View -->
<div id="mainView" class="hide">
<div class="tabs">
<div class="tab on" onclick="tab('e')" id="t_e">🤝 الصفقات</div>
<div class="tab" onclick="tab('w')" id="t_w">💰 المحفظة</div>
<div class="tab" onclick="tab('n')" id="t_n">🔔 <span id="notifC"></span>الإشعارات</div>
<div class="tab" onclick="tab('p')" id="t_p">👤 حسابي</div>
<div class="tab" onclick="tab('k')" id="t_k">📋 KYC</div>
<div class="tab hide" onclick="tab('a')" id="t_a">⚙️ الإدارة</div>
</div>

<!-- Tab: Escrows -->
<div id="v_e">
<div class="section"><h3>🤝 الصفقات</h3><div id="eList">جاري التحميل...</div>
<div style="text-align:center;margin-top:10px"><button class="bg" id="moreBtn" onclick="more()" style="display:none">عرض المزيد</button></div>
</div>
<div class="section"><h3>➕ إنشاء صفقة</h3>
<div class="fg"><label>اسم البائع</label><input id="sel" placeholder="اسم البائع"></div>
<div class="fg"><label>المبلغ</label><input type="number" id="amt" step="0.01" placeholder="0.00"></div>
<button class="bs" onclick="create()">🔒 إنشاء وقفل المبلغ</button>
</div>
<div class="section"><h3>🤖 وكيل الأمان</h3>
<div class="chat" id="aiChat">مرحباً. اسألني عن رصيدك أو ثقتك أو صفقاتك.</div>
<input id="aiIn" placeholder="اكتب رسالتك...">
<button class="bp" onclick="aiAsk()">إرسال</button>
</div>
</div>

<!-- Tab: Wallet -->
<div id="v_w" class="hide">
<div class="section"><h3>💰 المحفظة</h3>
<div class="row"><span>الرصيد:</span><b id="bal2" style="color:#10b981">0.00 $</b></div>
<div class="fg"><label>إيداع</label><input type="number" id="dep" step="0.01" placeholder="المبلغ"></div>
<button class="bs" onclick="deposit()">إيداع</button>
<div class="fg" style="margin-top:10px"><label>سحب</label><input type="number" id="wd" step="0.01" placeholder="المبلغ"></div>
<button class="bw" onclick="withdraw()">سحب</button>
<a href="/api/export/pdf" style="text-decoration:none;display:block"><button class="bp" style="margin-top:8px">📄 تصدير PDF</button></a>
<a href="/api/export/csv" style="text-decoration:none;display:block"><button class="bg" style="margin-top:6px">📥 تصدير CSV</button></a>
</div>
<div class="section"><h3>📜 آخر المعاملات</h3><div id="txList">جاري التحميل...</div></div>
</div>

<!-- Tab: Notifications -->
<div id="v_n" class="hide">
<div class="section"><h3>🔔 الإشعارات</h3>
<button class="bg" onclick="readAll()">تحديد الكل كمقروء</button>
<div id="notifList">جاري التحميل...</div>
</div>
</div>

<!-- Tab: Profile -->
<div id="v_p" class="hide">
<div class="section"><h3>👤 الملف الشخصي</h3>
<div class="row"><span>الاسم:</span><b id="pUser"></b></div>
<div class="row"><span>الدور:</span><b id="pRole"></b></div>
<div class="row"><span>الرصيد:</span><b id="pBal"></b></div>
<div class="row"><span>KYC:</span><b id="pKyc"></b></div>
<div class="row"><span>⭐ نقاط الثقة:</span><b id="pTrust" style="color:#10b981"></b></div>
<div class="row"><span>🎁 كود الإحالة:</span><b id="pRef" style="color:#fbbf24;font-family:monospace"></b></div>
<div class="row"><span>📧 البريد:</span><b id="pEmail" style="color:#38bdf8">--</b></div>
</div>
<div class="section"><h3>🔑 تغيير كلمة المرور</h3>
<div class="fg"><label>الحالية</label><input type="password" id="oldP"></div>
<div class="fg"><label>الجديدة</label><input type="password" id="newP"></div>
<button class="bs" onclick="changePwd()">تحديث</button>
</div>
<div class="section"><h3>📧 حفظ البريد للإشعارات</h3>
<div class="fg"><label>بريدك الإلكتروني</label><input id="emailInput" type="email" placeholder="you@example.com"></div>
<button class="bs" onclick="saveEmail()">💾 حفظ البريد</button>
<p id="emailMsg"></p>
</div>
</div>

<!-- Tab: KYC -->
<div id="v_k" class="hide">
<div class="section"><h3>📋 التحقق من الهوية (KYC)</h3>
<div class="row"><span>الحالة:</span><b id="kStat" style="color:#fbbf24">NONE</b></div>
<div class="fg"><label>الاسم الكامل</label><input id="kName" placeholder="كما في البطاقة"></div>
<div class="fg"><label>رقم الهوية</label><input id="kId" placeholder="رقم البطاقة/الباسبور"></div>
<button class="bs" onclick="kycSubmit()">📤 إرسال الطلب</button>
<p id="kycMsg"></p>
</div>
</div>

<!-- Tab: Admin -->
<div id="v_a" class="hide">
<div class="section admin" style="display:block">
<h3>⚙️ لوحة المسؤول</h3>
<a href="/vault" style="display:block;text-decoration:none;margin-bottom:10px"><button class="bgold">🔐 الخزنة الخاصة</button></a>
<a href="/admin/dashboard" style="display:block;text-decoration:none;margin-bottom:10px"><button class="bp">📊 لوحة التحليلية</button></a>
<div class="fg"><input id="banT" placeholder="اسم المستخدم"><div style="display:flex;gap:6px"><button class="bd" onclick="ban()">حظر</button><button class="bs" onclick="unban()">إلغاء</button></div></div>
<div class="fg"><input type="number" id="rId" placeholder="رقم الصفقة"><button class="bw" onclick="refund()">💸 استرداد للمشتري</button></div>

<!-- ========== 2FA Section ========== -->
<div class="card" id="twofaCard" style="margin-top:14px">
  <div class="card-title">🔐 التحقق بخطوتين (2FA)</div>
  <div id="twofaStatus" style="padding:10px;color:#f0ad4e;font-weight:bold">
    ⏳ جاري التحقق...
  </div>
  
  <div id="twofaSetupBox" style="display:none;margin-top:15px">
    <div style="background:#1a1f2e;padding:15px;border-radius:10px;text-align:center">
      <div style="color:#00d4aa;font-weight:bold;margin-bottom:10px">📱 امسح الـ QR بتطبيق Google Authenticator</div>
      <img id="twofaQR" style="max-width:220px;background:white;padding:10px;border-radius:10px" />
      <div style="color:#aaa;font-size:12px;margin-top:10px">
        أو استخدم المفتاح: <code id="twofaSecret" style="color:#00d4aa"></code>
      </div>
    </div>
    
    <div class="fg" style="margin-top:15px">
      <label>أدخل الكود من التطبيق (6 أرقام)</label>
      <input id="twofaCode" type="text" inputmode="numeric" maxlength="6" placeholder="000000" />
    </div>
    
    <button class="bp" onclick="verify2FA()" style="width:100%;padding:12px">
      ✅ تأكيد التفعيل
    </button>
  </div>
  
  <div id="twofaActions" style="display:none;margin-top:15px">
    <button id="twofaEnableBtn" class="bs" onclick="setup2FA()" style="width:100%;padding:12px">
      🔓 تفعيل 2FA
    </button>
    <button id="twofaDisableBtn" class="bw" onclick="disable2FA()" style="width:100%;padding:12px;margin-top:10px;display:none">
      🔒 إلغاء 2FA
    </button>
  </div>
</div>

<script>
async function check2FAStatus() {
  try {
    const r = await fetch('/api/2fa/status');
    const d = await r.json();
    const statusEl = document.getElementById('twofaStatus');
    const actionsEl = document.getElementById('twofaActions');
    const setupEl = document.getElementById('twofaSetupBox');
    const enableBtn = document.getElementById('twofaEnableBtn');
    const disableBtn = document.getElementById('twofaDisableBtn');
    
    if (d.enabled) {
      statusEl.innerHTML = '✅ 2FA مفعّل حالياً';
      statusEl.style.color = '#00d4aa';
      enableBtn.style.display = 'none';
      disableBtn.style.display = 'block';
    } else {
      statusEl.innerHTML = '⚠️ 2FA غير مفعّل - حسابك أقل أماناً';
      statusEl.style.color = '#f0ad4e';
      enableBtn.style.display = 'block';
      disableBtn.style.display = 'none';
    }
    setupEl.style.display = 'none';
    actionsEl.style.display = 'block';
  } catch(e) {
    document.getElementById('twofaStatus').innerHTML = '❌ خطأ في التحميل';
  }
}

async function setup2FA() {
  try {
    const r = await fetch('/api/2fa/setup', {method:'POST'});
    const d = await r.json();
    if (d.status === 'OK') {
      document.getElementById('twofaQR').src = d.qr_code;
      document.getElementById('twofaSecret').textContent = d.secret;
      document.getElementById('twofaSetupBox').style.display = 'block';
      document.getElementById('twofaActions').style.display = 'none';
    } else {
      alert('خطأ: ' + (d.message || 'فشل'));
    }
  } catch(e) { alert('خطأ في الاتصال'); }
}

async function verify2FA() {
  const code = document.getElementById('twofaCode').value.trim();
  if (code.length !== 6) { alert('أدخل 6 أرقام'); return; }
  try {
    const r = await fetch('/api/2fa/verify-setup', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({code: code})
    });
    const d = await r.json();
    if (d.status === 'OK') {
      alert('✅ تم تفعيل 2FA بنجاح!');
      if (d.backup_codes) {
        alert('احفظ الأكواد الاحتياطية:\n' + d.backup_codes.join('\n'));
      }
      check2FAStatus();
    } else {
      alert('خطأ: ' + (d.message || 'كود غير صحيح'));
    }
  } catch(e) { alert('خطأ في الاتصال'); }
}

async function disable2FA() {
  const code = prompt('أدخل كود 2FA الحالي لإلغاء التفعيل:');
  if (!code) return;
  try {
    const r = await fetch('/api/2fa/disable', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({code: code})
    });
    const d = await r.json();
    if (d.status === 'OK') {
      alert('✅ تم إلغاء 2FA');
      check2FAStatus();
    } else {
      alert('خطأ: ' + (d.message || 'فشل'));
    }
  } catch(e) { alert('خطأ في الاتصال'); }
}

// شغل التحقق لما الصفحة تفتح
setTimeout(check2FAStatus, 500);
</script>
<!-- ========== End 2FA Section ========== -->

<div style="display:flex;gap:6px"><button class="bg" onclick="stats()">📊 إحصائيات</button><button class="bg" onclick="users()">👥 المستخدمون</button></div>
<button class="bg" onclick="kycList()" style="margin-top:6px">📋 طلبات KYC</button>
</div>
</div>

<button class="bd" style="margin-top:15px" onclick="logout()">🚪 تسجيل الخروج</button>
</div>
</div>

<!-- Modals -->
<div id="chatModal" class="modal">
<div class="modal-c">
<h3 id="chatTitle">💬 المحادثة</h3>
<div class="chat" id="chatBox" style="height:300px"></div>
<div style="display:flex;gap:5px"><input id="chatIn" placeholder="اكتب..."><button class="bp" style="width:auto;padding:11px 15px" onclick="sendMsg()">➤</button></div>
<button class="bd" style="margin-top:10px" onclick="closeChat()">إغلاق</button>
</div>
</div>

<div id="msModal" class="modal">
<div class="modal-c">
<h3 id="msTitle">📋 المراحل</h3>
<div id="msList"></div>
<div class="fg"><label>عنوان المرحلة</label><input id="msTitleIn" placeholder="مثال: التصميم"></div>
<div class="fg"><label>المبلغ</label><input type="number" id="msAmtIn" step="0.01"></div>
<button class="bs" onclick="addMilestone()">➕ إضافة</button>
<button class="bd" style="margin-top:10px" onclick="closeMs()">إغلاق</button>
</div>
</div>

<div id="evModal" class="modal">
<div class="modal-c">
<h3 id="evTitle">📎 الأدلة</h3>
<div id="evList"></div>
<div class="fg"><label>المحتوى</label><textarea id="evContent" rows="3" placeholder="نص أو رابط"></textarea></div>
<div class="fg"><label>ملاحظة</label><input id="evNote" placeholder="اختياري"></div>
<button class="bs" onclick="addEvidence()">📤 رفع</button>
<button class="bd" style="margin-top:10px" onclick="closeEv()">إغلاق</button>
</div>
</div>

<script>
let me="", role="", page=0, csrf="", curChat=0, curMs=0, curEv=0;
function toast(m,t){const d=document.createElement('div');d.className='toast '+t;d.innerText=m;document.getElementById('toasts').appendChild(d);setTimeout(()=>d.remove(),3500);}
function api(u,m,b){return fetch(u,{method:m||'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:m==='GET'?undefined:JSON.stringify({...(b||{}),_csrf:csrf})}).then(r=>r.json());}
function show(id){document.querySelectorAll('[id^=v_]').forEach(x=>x.classList.add('hide'));const el=document.getElementById('v_'+id);if(el)el.classList.remove('hide');}
function tab(id){show(id);document.querySelectorAll('.tab').forEach(x=>x.classList.remove('on'));const t=document.getElementById('t_'+id);if(t)t.classList.add('on');
if(id==='n')loadNotifs();if(id==='w')loadWallet();if(id==='p')loadProfile();if(id==='k')loadKyc();}

function reg(){const u=document.getElementById('u').value.trim(),p=document.getElementById('p').value;
if(!u||!p)return toast('املأ الحقول','e');
api('/api/register','POST',{username:u,password:p}).then(d=>toast(d.message,d.status==='SUCCESS'?'s':'e'));}

function login(){const u=document.getElementById('u').value.trim(),p=document.getElementById('p').value;
api('/api/login','POST',{username:u,password:p}).then(d=>{
if(d.status!=='SUCCESS')return toast(d.message,'e');
me=u;role=d.role;csrf=d.csrf_token||'';
document.getElementById('who').innerText=u;
document.getElementById('bal').innerText=d.balance.toFixed(2)+' $';
document.getElementById('authView').classList.add('hide');
document.getElementById('mainView').classList.remove('hide');
if(d.role==='OWNER')document.getElementById('t_a').classList.remove('hide');
toast('مرحباً '+u,'s');loadEscrows(true);loadNotifs();});}

function logout(){api('/api/logout','POST',{}).then(()=>location.reload());}

function loadEscrows(reset){if(reset)page=0;
fetch('/api/escrows?offset='+(page*20)).then(r=>r.json()).then(d=>{
let b=document.getElementById('eList');if(reset)b.innerHTML='';
if(reset&&!d.escrows.length){b.innerHTML="<p style='color:#6b7280;font-size:13px'>لا صفقات.</p>";document.getElementById('moreBtn').style.display='none';return;}
d.escrows.forEach(e=>{
let c=e.status==='LOCKED_SECURE'?'locked':e.status==='DISPUTED'?'disputed':e.status==='RELEASED'?'released':e.status==='REFUNDED'?'refunded':'';
let a='';
if(e.status==='LOCKED_SECURE'&&e.buyer===me)a+='<button class="bs" style="padding:6px;font-size:11px;width:auto;margin:3px" onclick="release('+e.id+')">✅ تحرير</button>';
if(e.status==='LOCKED_SECURE'&&(e.buyer===me||e.seller===me))a+='<button class="bw" style="padding:6px;font-size:11px;width:auto;margin:3px" onclick="dispute('+e.id+')">⚠️ نزاع</button>';
if(e.status==='LOCKED_SECURE'&&e.seller===me)a+='<button class="bp" style="padding:6px;font-size:11px;width:auto;margin:3px" onclick="openMs('+e.id+')">📋 مراحل</button>';
if(e.buyer&&(e.buyer===me||e.seller===me))a+='<button class="bp" style="padding:6px;font-size:11px;width:auto;margin:3px" onclick="openChat('+e.id+')">💬 شات</button>';
if(e.status==='DISPUTED'||e.status==='LOCKED_SECURE')a+='<button class="bg" style="padding:6px;font-size:11px;width:auto;margin:3px" onclick="openEv('+e.id+')">📎 أدلة</button>';
if(e.status==='RELEASED'&&(e.buyer===me||e.seller===me))a+='<button class="bg" style="padding:6px;font-size:11px;width:auto;margin:3px" onclick="review('+e.id+')">⭐ قيّم</button>';
b.innerHTML+='<div class="item '+c+'"><b>#'+e.id+'</b> | بائع: <b>'+e.seller+'</b> | مشتري: <b>'+(e.buyer||'—')+'</b><br>المبلغ: <b>'+e.amount+'</b> | حالة: <b>'+e.status+'</b>'+(e.dispute_reason?'<br>سبب: '+e.dispute_reason:'')+'<div>'+a+'</div></div>';});
document.getElementById('moreBtn').style.display=d.escrows.length===20?'block':'none';});}

function more(){page++;loadEscrows(false);}

function create(){const s=document.getElementById('sel').value.trim(),a=parseFloat(document.getElementById('amt').value);
if(!s||isNaN(a)||a<=0)return toast('بيانات غير صالحة','e');
api('/api/escrow/create','POST',{seller:s,amount:a}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');if(d.status==='SUCCESS'){loadEscrows(true);loadWallet();}});}

function release(id){if(!confirm('تأكيد التحرير؟'))return;
api('/api/escrow/release','POST',{escrow_id:id}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');loadEscrows(true);loadWallet();});}

function dispute(id){const r=prompt('سبب النزاع:');if(!r)return;
api('/api/escrow/dispute','POST',{escrow_id:id,reason:r}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');loadEscrows(true);});}

function loadWallet(){api('/api/me','GET').then(d=>{if(d.status==='SUCCESS'){document.getElementById('bal2').innerText=d.user.balance.toFixed(2)+' $';}});
fetch('/api/transactions').then(r=>r.json()).then(d=>{
let b=document.getElementById('txList');b.innerHTML='';
if(!d.transactions||!d.transactions.length){b.innerHTML="<p style='color:#6b7280;font-size:13px'>لا معاملات.</p>";return;}
d.transactions.forEach(t=>{b.innerHTML+='<div class="item" style="border-right-color:#0284c7;font-size:12px"><b>'+t.type+'</b>: '+t.amount+'$ | '+(t.note||'')+'</div>';});});}

function deposit(){const a=parseFloat(document.getElementById('dep').value);if(isNaN(a)||a<=0)return toast('مبلغ غير صالح','e');
api('/api/wallet/deposit','POST',{amount:a}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');if(d.status==='SUCCESS'){document.getElementById('dep').value='';loadWallet();}});}

function withdraw(){const a=parseFloat(document.getElementById('wd').value);if(isNaN(a)||a<=0)return toast('مبلغ غير صالح','e');
api('/api/wallet/withdraw','POST',{amount:a}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');if(d.status==='SUCCESS'){document.getElementById('wd').value='';loadWallet();}});}

function loadNotifs(){fetch('/api/notifications').then(r=>r.json()).then(d=>{
if(d.status!=='SUCCESS')return;
document.getElementById('notifC').innerText=d.unread>0?'('+d.unread+') ':'';
let b=document.getElementById('notifList');b.innerHTML='';
if(!d.notifications.length){b.innerHTML="<p style='color:#6b7280;font-size:13px'>لا إشعارات.</p>";return;}
d.notifications.forEach(n=>{b.innerHTML+='<div class="item" style="border-right-color:'+(n.is_read?'#4b5563':'#38bdf8')+'"><b>'+n.title+'</b><br>'+(n.body||'')+'</div>';});});}

function readAll(){api('/api/notifications/read','POST',{}).then(()=>loadNotifs());}

function loadProfile(){api('/api/me','GET').then(d=>{if(d.status!=='SUCCESS')return;
document.getElementById('pUser').innerText=d.user.username;
document.getElementById('pRole').innerText=d.user.role;
document.getElementById('pBal').innerText=d.user.balance.toFixed(2)+' $';
document.getElementById('pKyc').innerText=d.user.kyc_status;
document.getElementById('pTrust').innerText=(d.user.trust_score||100)+'/1000';
document.getElementById('pRef').innerText=d.user.referral_code||'--';
document.getElementById('pEmail').innerText=d.user.email||'--';});}

function changePwd(){const o=document.getElementById('oldP').value,n=document.getElementById('newP').value;
api('/api/change-password','POST',{old:o,new:n}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');if(d.status==='SUCCESS'){document.getElementById('oldP').value='';document.getElementById('newP').value='';}});}

function saveEmail(){const e=document.getElementById('emailInput').value.trim();
if(!e||e.indexOf('@')===-1)return toast('بريد غير صالح','e');
api('/api/save-email','POST',{email:e}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');if(d.status==='SUCCESS')document.getElementById('pEmail').innerText=e;});}

function loadKyc(){fetch('/api/kyc/status').then(r=>r.json()).then(d=>{
let s='NONE';if(d.kyc)s=d.kyc.status;
document.getElementById('kStat').innerText=s;});}

function kycSubmit(){const n=document.getElementById('kName').value.trim(),i=document.getElementById('kId').value.trim();
if(!n||!i)return toast('املأ الحقول','e');
api('/api/kyc/submit','POST',{full_name:n,id_number:i}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');if(d.status==='SUCCESS')loadKyc();});}

function ban(){const t=document.getElementById('banT').value.trim();if(!t)return;
api('/api/admin/ban','POST',{target:t}).then(d=>toast(d.message,d.status==='SUCCESS'?'s':'e'));}

function unban(){const t=document.getElementById('banT').value.trim();if(!t)return;
api('/api/admin/unban','POST',{target:t}).then(d=>toast(d.message,d.status==='SUCCESS'?'s':'e'));}

function refund(){const id=parseInt(document.getElementById('rId').value);if(isNaN(id))return;
api('/api/admin/refund','POST',{escrow_id:id}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');loadEscrows(true);});}

function stats(){fetch('/api/admin/stats').then(r=>r.json()).then(d=>{if(d.status!=='SUCCESS')return toast(d.message,'e');
alert('👥 المستخدمون: '+d.users+'\n📋 الصفقات: '+d.escrows+'\n⚠️ النزاعات: '+d.disputes+'\n💰 الخزنة: '+d.balance+'$\n📈 العمولات: '+d.commission+'$');});}

function users(){fetch('/api/admin/users').then(r=>r.json()).then(d=>{if(d.status!=='SUCCESS')return toast(d.message,'e');
let t='المستخدمون:\n';d.users.forEach(u=>t+='- '+u.username+' | '+u.role+' | '+u.status+' | KYC:'+u.kyc_status+' | '+u.balance+'$\n');alert(t);});}

function kycList(){fetch('/api/admin/kyc/list').then(r=>r.json()).then(d=>{
if(d.status!=='SUCCESS')return toast(d.message,'e');
if(!d.submissions.length)return toast('لا طلبات','i');
d.submissions.forEach(s=>{
const dec=prompt('طلب من '+s.username+'\nالاسم: '+s.full_name+'\nرقم: '+s.id_number+'\n\nاكتب APPROVED أو REJECTED:');
if(dec==='APPROVED'||dec==='REJECTED')api('/api/admin/kyc/review','POST',{id:s.id,decision:dec}).then(x=>toast(x.message,x.status==='SUCCESS'?'s':'e'));});});}

function aiAsk(){const m=document.getElementById('aiIn').value.trim();if(!m)return;
const c=document.getElementById('aiChat');c.innerHTML+='<br><b>أنت:</b> '+m;
api('/api/ai/engine','POST',{message:m}).then(d=>{c.innerHTML+='<br><span style="color:#38bdf8"><b>الوكيل:</b> '+d.reply+'</span>';c.scrollTop=c.scrollHeight;document.getElementById('aiIn').value='';});}

function openChat(id){curChat=id;document.getElementById('chatModal').classList.add('on');document.getElementById('chatTitle').innerText='💬 محادثة #'+id;loadMsgs();}
function closeChat(){document.getElementById('chatModal').classList.remove('on');}
function loadMsgs(){fetch('/escrow/'+curChat+'/messages').then(r=>r.json()).then(d=>{
const b=document.getElementById('chatBox');b.innerHTML='';
if(d.status!=='SUCCESS')return;
d.messages.forEach(m=>{b.innerHTML+='<div style="margin:5px 0"><b style="color:'+(m.sender===me?'#38bdf8':'#f59e0b')+'">'+m.sender+':</b> '+m.body+'</div>';});
b.scrollTop=b.scrollHeight;});}
function sendMsg(){const t=document.getElementById('chatIn').value.trim();if(!t)return;
api('/escrow/'+curChat+'/messages','POST',{body:t}).then(d=>{if(d.status==='SUCCESS'){document.getElementById('chatIn').value='';loadMsgs();}});}

function openMs(id){curMs=id;document.getElementById('msModal').classList.add('on');document.getElementById('msTitle').innerText='📋 مراحل #'+id;loadMs();}
function closeMs(){document.getElementById('msModal').classList.remove('on');}
function loadMs(){fetch('/escrow/'+curMs+'/milestones').then(r=>r.json()).then(d=>{
const b=document.getElementById('msList');b.innerHTML='';
if(d.status!=='SUCCESS')return;
if(!d.milestones.length)b.innerHTML="<p style='color:#6b7280'>لا مراحل.</p>";
d.milestones.forEach(m=>{
let btn='';
if(m.status==='PENDING')btn='<button class="bs" style="padding:5px;font-size:11px;margin-top:5px" onclick="releaseMs('+m.id+')">✅ تحرير</button>';
b.innerHTML+='<div class="item '+(m.status==='RELEASED'?'released':'locked')+'"><b>'+m.order_num+'. '+m.title+'</b> - '+m.amount+'$ ('+m.status+')'+btn+'</div>';});});}
function addMilestone(){const t=document.getElementById('msTitleIn').value.trim(),a=parseFloat(document.getElementById('msAmtIn').value);
if(!t||isNaN(a)||a<=0)return toast('بيانات غير صالحة','e');
api('/escrow/'+curMs+'/milestone/add','POST',{title:t,amount:a}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');if(d.status==='SUCCESS'){document.getElementById('msTitleIn').value='';document.getElementById('msAmtIn').value='';loadMs();}});}
function releaseMs(mid){if(!confirm('تحرير هذه المرحلة؟'))return;
api('/milestone/'+mid+'/release','POST',{}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');loadMs();});}

function openEv(id){curEv=id;document.getElementById('evModal').classList.add('on');document.getElementById('evTitle').innerText='📎 أدلة #'+id;loadEv();}
function closeEv(){document.getElementById('evModal').classList.remove('on');}
function loadEv(){fetch('/escrow/'+curEv+'/evidence/list').then(r=>r.json()).then(d=>{
const b=document.getElementById('evList');b.innerHTML='';
if(d.status!=='SUCCESS')return;
if(!d.evidence.length)b.innerHTML="<p style='color:#6b7280'>لا أدلة.</p>";
d.evidence.forEach(e=>{b.innerHTML+='<div class="item"><b>'+e.uploader+':</b> '+e.content+'<br><small>'+(e.note||'')+'</small></div>';});});}
function addEvidence(){const c=document.getElementById('evContent').value.trim(),n=document.getElementById('evNote').value.trim();
if(!c)return toast('المحتوى مطلوب','e');
api('/escrow/'+curEv+'/evidence/add','POST',{content:c,note:n}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');if(d.status==='SUCCESS'){document.getElementById('evContent').value='';document.getElementById('evNote').value='';loadEv();}});}

function review(id){const r=prompt('تقييمك (1-5):');if(!r||r<1||r>5)return;
const c=prompt('تعليق (اختياري):')||'';
api('/review/add','POST',{escrow_id:id,rating:parseInt(r),comment:c}).then(d=>toast(d.message,d.status==='SUCCESS'?'s':'e'));}

loadEscrows(true);
if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js').catch(()=>{});}
</script>
</body></html>'''

# ============ OWNER PAGE ============
OWNER_HTML = r'''<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>🔐 بوابة المالك</title>
<style>
body{font-family:Tahoma;background:#07090e;color:#f1f5f9;padding:20px;margin:0}
.c{max-width:500px;margin:30px auto;background:#111827;padding:25px;border-radius:14px;border:1px solid #b45309}
h1{color:#fbbf24;text-align:center;font-size:22px;margin-bottom:15px}
.tabs{display:flex;gap:5px;margin-bottom:15px}
.tab{flex:1;padding:10px;background:#0b0f19;border:1px solid #374151;border-radius:8px;text-align:center;cursor:pointer;color:#94a3b8;font-size:13px}
.tab.on{background:#b45309;color:#fff}
.s{background:#0b0f19;padding:15px;border-radius:10px;margin-bottom:12px}
label{display:block;font-size:12px;color:#94a3b8;margin:8px 0 4px}
input{width:100%;padding:12px;background:#030712;color:#fff;border:1px solid #4b5563;border-radius:8px;font-size:14px;box-sizing:border-box}
button{width:100%;padding:12px;background:#b45309;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:bold;cursor:pointer;margin-top:12px}
.ok{color:#4ade80;font-size:13px;text-align:center;margin-top:10px}
.err{color:#f87171;font-size:13px;text-align:center;margin-top:10px}
.hide{display:none!important}
a{color:#38bdf8;text-decoration:none;display:block;text-align:center;margin-top:15px;font-size:13px}
</style></head>
<body><div class="c">
<h1>🔐 بوابة المالك</h1>
<div id="loginView">
<div class="s">
<label>كلمة مرور المالك</label>
<input type="password" id="p">
<button onclick="ol()">🔓 دخول</button>
<p id="m1" class="err"></p>
</div>
<a href="/">← العودة</a>
</div>
<div id="panelView" class="hide">
<div class="tabs">
<div class="tab on" id="tb1" onclick="st('pwd')">🔑 كلمة المرور</div>
<div class="tab" id="tb2" onclick="st('pin')">🔒 PIN</div>
</div>
<div id="tpwd">
<div class="s">
<label>الحالية</label><input type="password" id="op">
<label>الجديدة</label><input type="password" id="np">
<label>تأكيد</label><input type="password" id="np2">
<button onclick="cp()">💾 حفظ</button>
<p id="m2"></p>
</div></div>
<div id="tpin" class="hide">
<div class="s">
<label>PIN الحالي</label><input type="password" id="opn" inputmode="numeric">
<label>PIN الجديد</label><input type="password" id="npn" inputmode="numeric">
<label>تأكيد</label><input type="password" id="npn2" inputmode="numeric">
<button onclick="cpn()">💾 حفظ</button>
<p id="m3"></p>
</div></div>
<a href="/">← العودة</a>
</div>
</div>
<script>
function st(t){document.querySelectorAll('.tab').forEach(x=>x.classList.remove('on'));
document.getElementById(t==='pwd'?'tb1':'tb2').classList.add('on');
document.getElementById('tpwd').classList.toggle('hide',t!=='pwd');
document.getElementById('tpin').classList.toggle('hide',t!=='pin');}
function ol(){var p=document.getElementById('p').value;if(!p)return;
fetch('/api/owner/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})})
.then(r=>r.json()).then(d=>{if(d.status==='SUCCESS'){document.getElementById('loginView').classList.add('hide');document.getElementById('panelView').classList.remove('hide');}
else document.getElementById('m1').innerText=d.message;});}
function cp(){var o=document.getElementById('op').value,n=document.getElementById('np').value,n2=document.getElementById('np2').value;
if(!o||!n)return document.getElementById('m2').innerText='املأ الحقول';
if(n!==n2)return document.getElementById('m2').innerText='غير متطابقتين';
fetch('/api/owner/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old:o,new:n})})
.then(r=>r.json()).then(d=>{document.getElementById('m2').className=d.status==='SUCCESS'?'ok':'err';document.getElementById('m2').innerText=d.message;
if(d.status==='SUCCESS'){document.getElementById('op').value='';document.getElementById('np').value='';document.getElementById('np2').value='';}});}
function cpn(){var o=document.getElementById('opn').value,n=document.getElementById('npn').value,n2=document.getElementById('npn2').value;
if(!o||!n)return document.getElementById('m3').innerText='املأ الحقول';
if(n!==n2)return document.getElementById('m3').innerText='غير متطابقين';
fetch('/api/owner/change-pin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old:o,new:n})})
.then(r=>r.json()).then(d=>{document.getElementById('m3').className=d.status==='SUCCESS'?'ok':'err';document.getElementById('m3').innerText=d.message;
if(d.status==='SUCCESS'){document.getElementById('opn').value='';document.getElementById('npn').value='';document.getElementById('npn2').value='';}});}
</script></body></html>'''


# ============ VAULT PAGE ============
VAULT_HTML = r'''<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>🔐 الخزنة</title>
<style>
body{font-family:Tahoma;background:#030712;color:#e5e7eb;padding:15px;margin:0}
.c{max-width:900px;margin:auto}
.top{background:linear-gradient(135deg,#78350f,#451a03);padding:15px 20px;border-radius:12px;border:1px solid #b45309;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center}
.top h1{margin:0;font-size:18px;color:#fbbf24}
.top a{color:#fde68a;text-decoration:none;font-size:13px;padding:6px 12px;background:rgba(0,0,0,.3);border-radius:6px}
.pin{text-align:center;padding:40px 20px;background:#111827;border:2px solid #b45309;border-radius:12px;max-width:400px;margin:50px auto}
.pin h2{color:#fbbf24;margin-bottom:15px}
.pin input{width:100%;padding:15px;text-align:center;font-size:24px;letter-spacing:8px;background:#030712;color:#fbbf24;border:2px solid #b45309;border-radius:8px;margin-bottom:15px;box-sizing:border-box}
.pin button{width:100%;padding:12px;background:#b45309;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:bold;cursor:pointer}
.hide{display:none!important}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.stat{background:#111827;padding:16px;border-radius:10px;border:1px solid #374151}
.stat .l{color:#9ca3af;font-size:11px;margin-bottom:5px}
.stat .v{font-size:20px;font-weight:bold;color:#fbbf24}
</style></head>
<body><div class="c">
<div class="top"><h1>🔐 الخزنة الخاصة</h1><a href="/">← العودة</a></div>
<div id="pinGate" class="pin">
<h2>🔒 دخول محمي</h2>
<input type="password" id="pin" maxlength="8" inputmode="numeric">
<button onclick="unlock()">🔓 فتح</button>
<p id="pm" style="color:#f87171;font-size:13px;margin-top:10px"></p>
</div>
<div id="content" class="hide">
<div class="stats">
<div class="stat"><div class="l">💰 رصيد الخزنة</div><div class="v" id="s1">0</div></div>
<div class="stat"><div class="l">📈 العمولات</div><div class="v" id="s2">0</div></div>
<div class="stat"><div class="l">🔒 المقفلة</div><div class="v" id="s3">0</div></div>
<div class="stat"><div class="l">✅ المحررة</div><div class="v" id="s4">0</div></div>
<div class="stat"><div class="l">👥 المستخدمون</div><div class="v" id="s5">0</div></div>
</div>
</div>
</div>
<script>
function unlock(){var p=document.getElementById('pin').value;
fetch('/api/vault/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin:p})})
.then(r=>r.json()).then(d=>{if(d.status==='SUCCESS'){document.getElementById('pinGate').classList.add('hide');document.getElementById('content').classList.remove('hide');load();}
else document.getElementById('pm').innerText=d.message;});}
function load(){fetch('/api/vault/stats').then(r=>r.json()).then(d=>{
if(d.status!=='SUCCESS')return;
document.getElementById('s1').innerText=d.balance.toFixed(2)+'$';
document.getElementById('s2').innerText=d.commission.toFixed(2)+'$';
document.getElementById('s3').innerText=d.locked.toFixed(2)+'$';
document.getElementById('s4').innerText=d.released.toFixed(2)+'$';
document.getElementById('s5').innerText=d.users;});}
</script></body></html>'''


# ============ PUBLIC PROFILE ============
PROFILE_HTML = r'''<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>👤 {u}</title>
<style>
body{font-family:Tahoma;background:#07090e;color:#f1f5f9;padding:15px;margin:0}
.c{max-width:600px;margin:auto;background:#111827;padding:20px;border-radius:12px;border:1px solid #1f2937}
.av{width:80px;height:80px;background:linear-gradient(135deg,#0284c7,#10b981);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:36px;font-weight:bold;color:#fff;margin:0 auto 12px}
h1{color:#38bdf8;text-align:center;font-size:22px;margin-bottom:5px}
.r{text-align:center;color:#9ca3af;font-size:12px;margin-bottom:20px}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:15px}
.st{background:#1f2937;padding:12px;border-radius:8px;border:1px solid #374151;text-align:center}
.st .l{color:#9ca3af;font-size:11px;margin-bottom:5px}
.st .v{font-size:18px;font-weight:bold;color:#10b981}
.st.g .v{color:#fbbf24}
.sec{background:#1f2937;padding:15px;border-radius:10px;border:1px solid #374151;margin-bottom:12px}
.sec h3{color:#cbd5e1;margin-bottom:12px;font-size:15px;border-bottom:1px solid #374151;padding-bottom:8px}
.it{background:#0b0f19;padding:12px;margin-top:8px;border-radius:8px;border-right:4px solid #fbbf24;font-size:13px}
.b{display:inline-block;background:#10b981;color:#fff;padding:3px 10px;border-radius:20px;font-size:11px;margin:2px}
.b.g{background:#fbbf24;color:#000}
.back{display:block;text-align:center;color:#38bdf8;text-decoration:none;margin-top:15px;font-size:13px}
</style></head>
<body><div class="c">
<div class="av">{initial}</div>
<h1>{u}</h1>
<div class="r">{badges}</div>
<div class="stats">
<div class="st g"><div class="l">⭐ Trust</div><div class="v">{trust}</div></div>
<div class="st"><div class="l">📊 صفقات</div><div class="v">{deals}</div></div>
<div class="st"><div class="l">⭐ تقييم</div><div class="v">{avg}/5</div></div>
<div class="st"><div class="l">📝 عدد</div><div class="v">{cnt}</div></div>
</div>
<div class="sec"><h3>⭐ التقييمات</h3>{reviews}</div>
<a href="/" class="back">← العودة</a>
</div></body></html>'''


# ============ OWNER ROUTES ============
@app.route('/owner')
def owner_page(): return render_template_string(OWNER_HTML)

@app.route('/api/owner/login', methods=['POST'])
def api_owner_login():
    p = (request.get_json(silent=True) or {}).get('password', '')
    c = get_db()
    r = c.execute("SELECT * FROM users WHERE username=?", (MASTER_OWNER,)).fetchone()
    c.close()
    if not r or not check_password_hash(r['password_hash'], p):
        time.sleep(1); log_event('OWNER_LOGIN_FAILED', MASTER_OWNER)
        return jsonify({'status':'ERROR','message':'خاطئة'})
    session.clear(); session.permanent = True
    session['user'] = MASTER_OWNER
    session['user_id'] = r['id']
    session['role'] = 'OWNER'
    session['owner_verified'] = True
    log_event('OWNER_LOGIN', MASTER_OWNER)
    return jsonify({'status':'SUCCESS'})

@app.route('/api/owner/change-password', methods=['POST'])
def api_owner_pwd():
    if not (session.get('user_id') and session.get('owner_verified')): 
        return jsonify({'status':'ERROR','message':'غير مصرح'})
    d = request.get_json(silent=True) or {}
    ok, msg = valid_pass(d.get('new',''))
    if not ok: return jsonify({'status':'ERROR','message':msg})
    c = get_db()
    r = c.execute("SELECT password_hash FROM users WHERE username=?", (MASTER_OWNER,)).fetchone()
    if not r or not check_password_hash(r['password_hash'], d.get('old','')):
        c.close(); return jsonify({'status':'ERROR','message':'كلمة المرور الحالية خاطئة'})
    c.execute("UPDATE users SET password_hash=? WHERE username=?", (generate_password_hash(d['new']), MASTER_OWNER))
    c.close()
    log_event('OWNER_PWD_CHANGED', MASTER_OWNER)
    return jsonify({'status':'SUCCESS','message':'تم التغيير'})

@app.route('/api/owner/change-pin', methods=['POST'])
def api_owner_pin():
    global VAULT_PIN
    if not (session.get('user_id') and session.get('owner_verified')): 
        return jsonify({'status':'ERROR','message':'غير مصرح'})
    d = request.get_json(silent=True) or {}
    old = d.get('old','')
    new = d.get('new','')
    if not re.match(r'^\d{4,8}$', new):
        return jsonify({'status':'ERROR','message':'PIN: 4-8 أرقام'})
    if old != VAULT_PIN:
        time.sleep(1); return jsonify({'status':'ERROR','message':'PIN خاطئ'})
    VAULT_PIN = new
    try:
        with open('.vault_pin', 'w') as f: f.write(new)
    except: pass
    log_event('OWNER_PIN_CHANGED', MASTER_OWNER)
    return jsonify({'status':'SUCCESS','message':'تم تغيير PIN'})

# ============ VAULT ROUTES ============
@app.route('/vault')
def vault_page():
    if session.get('user_id') is None or session.get('user') != MASTER_OWNER:
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>🚫 مرفوض</h1>", 403
    return render_template_string(VAULT_HTML)

@app.route('/api/vault/unlock', methods=['POST'])
def api_vault_unlock():
    if session.get('user') != MASTER_OWNER:
        return jsonify({'status':'ERROR','message':'مرفوض'})
    pin = (request.get_json(silent=True) or {}).get('pin', '')
    if pin == VAULT_PIN:
        session['vault_ok'] = True
        log_event('VAULT_UNLOCK', MASTER_OWNER)
        return jsonify({'status':'SUCCESS'})
    time.sleep(1)
    log_event('VAULT_FAILED', MASTER_OWNER)
    return jsonify({'status':'ERROR','message':'رمز خطأ'})

@app.route('/api/vault/stats', methods=['GET'])
@login_required
def api_vault_stats():
    if not vault_unlocked(): return jsonify({'status':'ERROR','message':'مقفلة'})
    c = get_db()
    t = c.execute("SELECT * FROM treasury WHERE id=1").fetchone()
    u = c.execute("SELECT COUNT(*) as n FROM users").fetchone()['n']
    c.close()
    return jsonify({'status':'SUCCESS','balance':t['balance'],'commission':t['total_commission'],
                    'locked':t['total_locked'],'released':t['total_released'],
                    'refunded':t['total_refunded'],'rate':t['commission_rate'],'users':u})

# ============ PUBLIC PROFILE ============
@app.route('/u/<username>')
def public_profile(username):
    c = get_db()
    u = c.execute("SELECT username, role, kyc_status, trust_score, successful_deals FROM users WHERE username=?", (username,)).fetchone()
    if not u:
        c.close(); return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>🚫 غير موجود</h1>"
    reviews = c.execute("SELECT * FROM reviews WHERE reviewee=? ORDER BY id DESC LIMIT 20", (username,)).fetchall()
    avg = c.execute("SELECT AVG(rating) as a, COUNT(*) as n FROM reviews WHERE reviewee=?", (username,)).fetchone()
    c.close()
    initial = username[0].upper() if username else '?'
    badges = ''
    if u['role'] == 'OWNER': badges += "<span class='b g'>👑 مالك المنصة</span>"
    if u['kyc_status'] == 'APPROVED': badges += "<span class='b'>✅ موثق KYC</span>"
    if not badges: badges = "<span class='b' style='background:#374151'>👤 مستخدم</span>"
    rev_html = ''
    if reviews:
        for r in reviews:
            rev_html += f"<div class='it'><b>{r['reviewer']}</b><br>{'⭐'*r['rating']}<br>{(r['comment'] or '')}</div>"
    else:
        rev_html = "<p style='color:#6b7280;text-align:center'>لا تقييمات</p>"
    html = PROFILE_HTML.replace('{u}', u['username']).replace('{initial}', initial).replace('{badges}', badges)
    html = html.replace('{trust}', str(u['trust_score'] or 100)).replace('{deals}', str(u['successful_deals'] or 0))
    html = html.replace('{avg}', str(round(avg['a'],1) if avg['a'] else 0)).replace('{cnt}', str(avg['n']))
    html = html.replace('{reviews}', rev_html)
    return html


# ============ ROOT ROUTE ============
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


# ============ MAIN BLOCK ============


# ============================================================
#                    Security Endpoints
# ============================================================
@app.route('/health')
def health_check():
    return jsonify({'status': 'ok', 'time': int(time.time())})


@app.route('/api/security/scan', methods=['POST'])
@login_required
def api_security_scan():
    """يفحص المشروع بحثاً عن أسرار مكشوفة - للمالك فقط"""
    if not is_admin():
        return jsonify({'status': 'ERROR', 'message': 'مرفوض'}), 403
    try:
        results = scan_directory('.')
        total_secrets = sum(len(r['secrets']) for r in results)
        if results:
            threat.activate_lockdown(1)  # إغلاق مؤقت للحماية
            log_event('SECRET_LEAK_DETECTED', session['user'])
        return jsonify({
            'status': 'SUCCESS',
            'files_with_secrets': len(results),
            'total_secrets': total_secrets,
            'details': results[:10]
        })
    except Exception as e:
        return jsonify({'status': 'ERROR', 'message': str(e)})


@app.route('/api/security/status', methods=['GET'])
@login_required
def api_security_status():
    """حالة الأمان الحالية - للمالك فقط"""
    if not is_admin():
        return jsonify({'status': 'ERROR', 'message': 'مرفوض'}), 403
    with threat.lock:
        return jsonify({
            'status': 'SUCCESS',
            'lockdown': threat.lockdown,
            'lockdown_until': threat.lockdown_until,
            'banned_ips': len(threat.banned),
            'active_attempts': len(threat.attempts),
            'time': int(time.time())
        })


@app.route('/api/security/lockdown', methods=['POST'])
@login_required
def api_security_lockdown():
    """تفعيل الإغلاق الفوري"""
    if not is_admin():
        return jsonify({'status': 'ERROR', 'message': 'مرفوض'}), 403
    minutes = int((request.get_json(silent=True) or {}).get('minutes', 30))
    threat.activate_lockdown(minutes)
    log_event('MANUAL_LOCKDOWN', session['user'])
    return jsonify({'status': 'SUCCESS', 'message': f'Lockdown activated for {minutes}min'})


@app.route('/api/security/unlock', methods=['POST'])
@login_required
def api_security_unlock():
    """إلغاء الإغلاق"""
    if not is_admin():
        return jsonify({'status': 'ERROR', 'message': 'مرفوض'}), 403
    with threat.lock:
        threat.lockdown = False
        threat.lockdown_until = 0
    log_event('MANUAL_UNLOCK', session['user'])
    return jsonify({'status': 'SUCCESS', 'message': 'Lockdown lifted'})




# ============================================================
#                    Debug Endpoint (للمالك فقط)
# ============================================================
@app.route('/api/debug', methods=['GET'])
def debug_info():
    """يعرض معلومات الاتصال بالخادم - محمي بكلمة سرية"""
    from flask import request
    secret = request.args.get('key', '')
    if secret != 'EssamDebug2026':
        return jsonify({'status': 'ERROR', 'message': 'Access denied'}), 403
    
    import platform
    info = {
        'status': 'SUCCESS',
        'USE_POSTGRES': USE_POSTGRES,
        'DATABASE_URL_set': bool(DATABASE_URL),
        'DATABASE_URL_length': len(DATABASE_URL) if DATABASE_URL else 0,
        'DATABASE_URL_prefix': DATABASE_URL[:30] + '...' if DATABASE_URL else 'EMPTY',
        'DATABASE_URL_suffix': '...' + DATABASE_URL[-20:] if DATABASE_URL else 'EMPTY',
        'IS_PRODUCTION': IS_PRODUCTION,
        'THREAT_ENABLED': os.environ.get('THREAT_ENABLED', '0'),
        'GMAIL_USER': GMAIL_USER or 'EMPTY',
        'RESEND_KEY_set': bool(os.environ.get('RESEND_API_KEY')),
        'RESEND_FROM': os.environ.get('RESEND_FROM', 'EMPTY'),
        'TG_TOKEN_set': bool(TG_TOKEN),
        'python_version': platform.python_version(),
        'platform': platform.system(),
    }
    
    # اختبار اتصال قاعدة البيانات
    try:
        c = get_db()
        cur = c.cursor()
        cur.execute("SELECT COUNT(*) as n FROM users")
        users_count = cur.fetchone()['n']
        cur.execute("SELECT username, role FROM users ORDER BY id LIMIT 5")
        sample = [{'username': r['username'], 'role': r['role']} for r in cur.fetchall()]
        c.close()
        info['db_connection'] = 'OK'
        info['users_count'] = users_count
        info['sample_users'] = sample
    except Exception as e:
        info['db_connection'] = f'ERROR: {str(e)[:200]}'
    
    return jsonify(info)




# ============================================================
#                    Reset Owner Password (Emergency)
# ============================================================


# تعريف _placeholder (مطلوب لـ 2FA)
def _placeholder():
    return '%s' if USE_POSTGRES else '?'


# تسجيل مسارات 2FA
try:
    if setup_2fa_routes:
        setup_2fa_routes(app, get_db, _placeholder, login_required)
        print('[2FA] تم تسجيل المسارات بنجاح')
except Exception as _e:
    print(f'[2FA] تحذير: {_e}')
