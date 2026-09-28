import os, re, threading, time, secrets, sqlite3, pyotp, io, base64
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template_string, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash


# ============ تحميل متغيرات البيئة من .env ============
def _load_env():
    import os as _os
    env_path = _os.path.join(_os.path.dirname(__file__), '.env')
    if not _os.path.exists(env_path):
        return
    with open(env_path, 'r') as f:
        for line in f:
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                k, v = line.split('=', 1)
                if k not in _os.environ:
                    _os.environ[k] = v

_load_env()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', PERMANENT_SESSION_LIFETIME=timedelta(hours=2))

DATABASE = 'enterprise_escrow.db'
MASTER_OWNER = "EssamElkomy369"
VAULT_PIN = os.environ.get("VAULT_PIN", "369246")
MAX_ESCROW = 10000.0
db_lock = threading.Lock()
login_attempts, register_attempts = {}, {}
banned_ips = {}
last_cleanup = time.time()

def is_ip_banned(ip):
    if ip not in banned_ips: return False
    if time.time() > banned_ips[ip]:
        del banned_ips[ip]
        return False
    return True

def ban_ip(ip, minutes=30):
    banned_ips[ip] = time.time() + (minutes * 60)

def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

def get_db():
    conn = sqlite3.connect(DATABASE, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=8000")
    return conn

def init_db():
    conn = get_db(); c = conn.cursor()
    try:
        c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, balance REAL DEFAULT 500.0, role TEXT DEFAULT "CLIENT", status TEXT DEFAULT "ACTIVE", kyc_status TEXT DEFAULT "NONE", referral_code TEXT, trust_score INTEGER DEFAULT 100, successful_deals INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS escrows (id INTEGER PRIMARY KEY AUTOINCREMENT, seller TEXT NOT NULL, buyer TEXT, amount REAL NOT NULL, status TEXT DEFAULT "PENDING", dispute_reason TEXT DEFAULT "", created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, type TEXT NOT NULL, amount REAL NOT NULL, note TEXT DEFAULT "", timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, username TEXT, ip TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, title TEXT NOT NULL, body TEXT DEFAULT "", is_read INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS treasury (id INTEGER PRIMARY KEY AUTOINCREMENT, balance REAL DEFAULT 0.0, total_commission REAL DEFAULT 0.0, total_locked REAL DEFAULT 0.0, total_released REAL DEFAULT 0.0, commission_rate REAL DEFAULT 2.0, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS twofa (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, secret TEXT NOT NULL, enabled INTEGER DEFAULT 0, backup_code TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS kyc_submissions (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, full_name TEXT, id_number TEXT, status TEXT DEFAULT "PENDING", submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP)')
        c.execute('CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, escrow_id INTEGER NOT NULL, uploader TEXT NOT NULL, content TEXT NOT NULL, note TEXT DEFAULT "", created_at DATETIME DEFAULT CURRENT_TIMESTAMP)')
        c.execute("SELECT COUNT(*) as n FROM treasury")
        if c.fetchone()["n"] == 0:
            c.execute("INSERT INTO treasury (balance, commission_rate) VALUES (0.0, 2.0)")
        c.execute("SELECT * FROM users WHERE username = ?", (MASTER_OWNER,))
        if not c.fetchone():
            h = generate_password_hash("EssamElkomy369")
            c.execute("INSERT INTO users (username, password_hash, balance, role, status, referral_code) VALUES (?, ?, ?, ?, ?, ?)", (MASTER_OWNER, h, 100000.0, "OWNER", "ACTIVE", "OWNER001"))
        conn.commit()
    except Exception as e:
        print(f"[INIT] {e}")
    finally:
        conn.close()

init_db()

def log_event(event, username=None):
    try:
        conn = get_db()
        conn.execute("INSERT INTO logs (event, username, ip) VALUES (?, ?, ?)", (event, username, request.remote_addr if request else "N/A"))
        conn.close()
    except: pass


def email_notify(username, subject, body_html):
    import smtplib as _smtp
    from email.mime.text import MIMEText as _MIMEText
    from email.mime.multipart import MIMEMultipart as _MIMEMultipart
    import re as _re
    try:
        with open(__file__, "r") as _f:
            _src = _f.read()
        _u = _re.search(r'GMAIL_USER\s*=\s*"([^"]+)"', _src)
        _p = _re.search(r'GMAIL_PASS\s*=\s*"([^"]+)"', _src)
        if not _u or not _p:
            print("[EMAIL] config missing")
            return False
        USER_ = _u.group(1)
        PASS_ = _p.group(1)
        conn = get_db()
        r = conn.execute("SELECT email FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if not r: return False
        try: to = r["email"]
        except: return False
        if not to: return False
        msg = _MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = USER_
        msg["To"] = to
        msg.attach(_MIMEText(body_html, "html", "utf-8"))
        with _smtp.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as s:
            s.login(USER_, PASS_)
            s.send_message(msg)
        print("[EMAIL] sent to " + to)
        return True
    except Exception as e:
        print("[EMAIL-ERR] " + str(e))
        return False


def notify(u, title, body=''):
    try:
        conn = get_db()
        conn.execute("INSERT INTO notifications (username, title, body) VALUES (?, ?, ?)", (u, title, body))
        conn.close()
    except: pass
    try:
        if u == MASTER_OWNER:
            send_telegram("<b>" + str(title) + "</b>\n" + str(body))
    except: pass
    # إرسال بريد إلكتروني للمستخدم
    try:
        result = email_notify(u, title, "<p>" + str(body) + "</p>")
        print("[NOTIFY] email_notify(" + str(u) + ") -> " + str(result))
    except Exception as _e:
        print("[NOTIFY-ERR] " + str(_e))

def valid_user(u):
    return u and 3 <= len(u) <= 30 and re.match(r'^[a-zA-Z0-9_]+$', u)

def valid_pass(p):
    if len(p) < 8: return False, "8 أحرف على الأقل"
    if not re.search(r'[A-Za-z]', p): return False, "يجب حرف"
    if not re.search(r'\d', p): return False, "يجب رقم"
    return True, "OK"

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if 'user' not in session:
            return jsonify({"status": "ERROR", "message": "سجل الدخول أولاً"})
        return f(*a, **k)
    return w

def is_admin():
    return session.get('role') == 'OWNER' and session.get('user') == MASTER_OWNER

def vault_unlocked():
    return session.get('user') == MASTER_OWNER and session.get('vault_unlocked') is True

def owner_verified():
    return session.get('user') == MASTER_OWNER and session.get('owner_verified') is True

def check_limit(store, key, max_a, window):
    now = time.time()
    store.setdefault(key, [])
    store[key] = [t for t in store[key] if now - t < window]
    if len(store[key]) >= max_a: return False
    store[key].append(now)
    return True

def compute_trust(u):
    conn = get_db()
    r = conn.execute("SELECT kyc_status FROM users WHERE username=?", (u,)).fetchone()
    if not r: conn.close(); return 100
    s = 100
    if r["kyc_status"] == "APPROVED": s += 200
    d = conn.execute("SELECT COUNT(*) as c FROM escrows WHERE seller=? AND status='RELEASED'", (u,)).fetchone()["c"]
    s += min(d * 5, 300)
    conn.close()
    return max(0, min(1000, s))

@app.route('/api/register', methods=['POST'])
def api_register():
    d = request.get_json(silent=True) or {}
    u = (d.get("username") or "").strip()
    p = d.get("password") or ""
    if not check_limit(register_attempts, f"r_{request.remote_addr}", 5, 3600):
        return jsonify({"status": "ERROR", "message": "محاولات كثيرة"})
    if not valid_user(u): return jsonify({"status": "ERROR", "message": "اسم غير صالح"})
    ok, msg = valid_pass(p)
    if not ok: return jsonify({"status": "ERROR", "message": msg})
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        ref = secrets.token_hex(4).upper()
        conn.execute("INSERT INTO users (username, password_hash, balance, referral_code) VALUES (?, ?, ?, ?)", (u, generate_password_hash(p), 500.0, ref))
        conn.execute("INSERT INTO transactions (username, type, amount, note) VALUES (?, ?, ?, ?)", (u, "BONUS", 500.0, "رصيد ترحيبي"))
        conn.execute("COMMIT")
        log_event("REGISTER", u)
        return jsonify({"status": "SUCCESS", "message": f"تم! كود إحالتك: {ref}"})
    except Exception:
        if conn.in_transaction: conn.execute("ROLLBACK")
        return jsonify({"status": "ERROR", "message": "الاسم مستخدم"})
    finally: conn.close()

@app.route('/api/login', methods=['POST'])
def api_login():
    d = request.get_json(silent=True) or {}
    u = (d.get("username") or "").strip()
    p = d.get("password") or ""
    if not check_limit(login_attempts, f"l_{request.remote_addr}", 10, 300):
        return jsonify({"status": "ERROR", "message": "محاولات كثيرة"})
    conn = get_db()
    r = conn.execute("SELECT * FROM users WHERE username = ?", (u,)).fetchone()
    conn.close()
    if r and check_password_hash(r["password_hash"], p):
        if r["status"] == "BANNED":
            return jsonify({"status": "ERROR", "message": "محظور"})
        session.clear(); session.permanent = True
        session['user'] = u
        session['role'] = r["role"]
        log_event("LOGIN", u)
        return jsonify({"status": "SUCCESS", "balance": r["balance"], "role": r["role"], "trust": r["trust_score"]})
    return jsonify({"status": "ERROR", "message": "بيانات خاطئة"})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({"status": "SUCCESS"})

@app.route('/api/me')
@login_required
def api_me():
    conn = get_db()
    r = conn.execute("SELECT username, balance, role, kyc_status, referral_code, trust_score FROM users WHERE username=?", (session['user'],)).fetchone()
    conn.close()
    return jsonify({"status": "SUCCESS", "user": dict(r)})

@app.route('/api/change-password', methods=['POST'])
@login_required
def api_change_pwd():
    d = request.get_json(silent=True) or {}
    old, new = d.get("old", ""), d.get("new", "")
    ok, msg = valid_pass(new)
    if not ok: return jsonify({"status": "ERROR", "message": msg})
    conn = get_db()
    r = conn.execute("SELECT password_hash FROM users WHERE username=?", (session['user'],)).fetchone()
    if not r or not check_password_hash(r["password_hash"], old):
        conn.close()
        return jsonify({"status": "ERROR", "message": "كلمة المرور الحالية خاطئة"})
    conn.execute("UPDATE users SET password_hash=? WHERE username=?", (generate_password_hash(new), session['user']))
    conn.close()
    return jsonify({"status": "SUCCESS", "message": "تم التغيير"})

@app.route('/api/me/trust')
@login_required
def api_my_trust():
    return jsonify({"status": "SUCCESS", "trust_score": compute_trust(session["user"])})

@app.route('/api/escrows')
def api_escrows():
    conn = get_db()
    rows = conn.execute("SELECT * FROM escrows ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    return jsonify({"escrows": [dict(r) for r in rows]})

@app.route('/api/escrow/create', methods=['POST'])
@login_required
def api_escrow_create():
    d = request.get_json(silent=True) or {}
    seller = (d.get("seller") or "").strip()
    try: amount = round(float(d.get("amount", 0)), 2)
    except: return jsonify({"status": "ERROR", "message": "مبلغ غير صالح"})
    buyer = session['user']
    if not seller or amount <= 0: return jsonify({"status": "ERROR", "message": "بيانات ناقصة"})
    if buyer == seller: return jsonify({"status": "ERROR", "message": "لا صفقة مع نفسك"})
    if amount > MAX_ESCROW: return jsonify({"status": "ERROR", "message": f"الحد {MAX_ESCROW}$"})
    with db_lock:
        conn = get_db(); c = conn.cursor()
        try:
            c.execute("BEGIN IMMEDIATE")
            b = c.execute("SELECT balance FROM users WHERE username=?", (buyer,)).fetchone()
            if not b or b["balance"] < amount:
                c.execute("ROLLBACK"); return jsonify({"status": "ERROR", "message": "رصيدك لا يكفي"})
            if not c.execute("SELECT 1 FROM users WHERE username=?", (seller,)).fetchone():
                c.execute("ROLLBACK"); return jsonify({"status": "ERROR", "message": "البائع غير موجود"})
            c.execute("UPDATE users SET balance=balance-? WHERE username=?", (amount, buyer))
            c.execute("INSERT INTO escrows (seller, buyer, amount, status) VALUES (?,?,?,'LOCKED_SECURE')", (seller, buyer, amount))
            eid = c.lastrowid
            c.execute("INSERT INTO transactions (username, type, amount, note) VALUES (?,?,?,?)", (buyer, "LOCK", -amount, f"#{eid}"))
            c.execute("UPDATE treasury SET total_locked=total_locked+? WHERE id=1", (amount,))
            c.execute("COMMIT")
            notify(seller, "🔔 صفقة جديدة", f"#{eid} بمبلغ {amount}$")
            return jsonify({"status": "SUCCESS", "message": f"تم #{eid}"})
        except Exception as e:
            if conn.in_transaction: c.execute("ROLLBACK")
            return jsonify({"status": "ERROR", "message": str(e)})
        finally: conn.close()

@app.route('/api/escrow/release', methods=['POST'])
@login_required
def api_escrow_release():
    d = request.get_json(silent=True) or {}
    try: eid = int(d.get("escrow_id"))
    except: return jsonify({"status": "ERROR", "message": "رقم غير صالح"})
    with db_lock:
        conn = get_db(); c = conn.cursor()
        try:
            c.execute("BEGIN IMMEDIATE")
            e = c.execute("SELECT * FROM escrows WHERE id=? AND status='LOCKED_SECURE'", (eid,)).fetchone()
            if not e:
                c.execute("ROLLBACK"); return jsonify({"status": "ERROR", "message": "غير متاحة"})
            if e["buyer"] != session['user']:
                c.execute("ROLLBACK"); return jsonify({"status": "ERROR", "message": "المشتري فقط"})
            rate = c.execute("SELECT commission_rate FROM treasury WHERE id=1").fetchone()["commission_rate"]
            comm = round(e["amount"] * rate / 100.0, 2)
            net = round(e["amount"] - comm, 2)
            c.execute("UPDATE users SET balance=balance+?, successful_deals=successful_deals+1, trust_score=MIN(1000, trust_score+10) WHERE username=?", (net, e["seller"]))
            c.execute("UPDATE escrows SET status='RELEASED', updated_at=CURRENT_TIMESTAMP WHERE id=?", (eid,))
            c.execute("UPDATE treasury SET balance=balance+?, total_commission=total_commission+?, total_locked=total_locked-?, total_released=total_released+? WHERE id=1", (comm, comm, e["amount"], e["amount"]))
            c.execute("INSERT INTO transactions (username, type, amount, note) VALUES (?,?,?,?)", (e["seller"], "RELEASE", net, f"#{eid}"))
            c.execute("COMMIT")
            notify(e["seller"], "💰 تحرير", f"استلمت {net}$")
            return jsonify({"status": "SUCCESS", "message": f"تم تحرير {net}$"})
        except Exception as ex:
            if conn.in_transaction: c.execute("ROLLBACK")
            return jsonify({"status": "ERROR", "message": str(ex)})
        finally: conn.close()

@app.route('/api/escrow/dispute', methods=['POST'])
@login_required
def api_escrow_dispute():
    d = request.get_json(silent=True) or {}
    try: eid = int(d.get("escrow_id"))
    except: return jsonify({"status": "ERROR", "message": "رقم غير صالح"})
    reason = (d.get("reason") or "").strip()[:500]
    if not reason: return jsonify({"status": "ERROR", "message": "السبب مطلوب"})
    u = session['user']
    conn = get_db(); c = conn.cursor()
    try:
        c.execute("BEGIN IMMEDIATE")
        e = c.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
        if not e or u not in (e["seller"], e["buyer"]):
            if conn.in_transaction: c.execute("ROLLBACK")
            return jsonify({"status": "ERROR", "message": "غير مخول"})
        c.execute("UPDATE escrows SET status='DISPUTED', dispute_reason=? WHERE id=?", (reason, eid))
        c.execute("COMMIT")
        notify(MASTER_OWNER, "🚨 نزاع", f"#{eid}")
        return jsonify({"status": "SUCCESS", "message": "تم فتح النزاع"})
    except Exception as ex:
        if conn.in_transaction: c.execute("ROLLBACK")
        return jsonify({"status": "ERROR", "message": str(ex)})
    finally: conn.close()

@app.route('/api/transactions')
@login_required
def api_txs():
    conn = get_db()
    rows = conn.execute("SELECT * FROM transactions WHERE username=? ORDER BY id DESC LIMIT 30", (session['user'],)).fetchall()
    conn.close()
    return jsonify({"status": "SUCCESS", "transactions": [dict(r) for r in rows]})

@app.route('/api/notifications')
@login_required
def api_notifs():
    conn = get_db()
    rows = conn.execute("SELECT * FROM notifications WHERE username=? ORDER BY id DESC LIMIT 30", (session['user'],)).fetchall()
    conn.close()
    return jsonify({"status": "SUCCESS", "notifications": [dict(r) for r in rows]})

@app.route('/api/wallet/deposit', methods=['POST'])
@login_required
def api_deposit():
    try: a = round(float((request.get_json(silent=True) or {}).get("amount", 0)), 2)
    except: return jsonify({"status": "ERROR", "message": "مبلغ غير صالح"})
    if a <= 0 or a > 10000: return jsonify({"status": "ERROR", "message": "المبلغ 1-10000"})
    with db_lock:
        conn = get_db()
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE users SET balance=balance+? WHERE username=?", (a, session['user']))
        conn.execute("INSERT INTO transactions (username,type,amount,note) VALUES (?,?,?,?)", (session['user'], "DEPOSIT", a, "إيداع"))
        conn.commit(); conn.close()
    return jsonify({"status": "SUCCESS", "message": f"تم إيداع {a}$"})

@app.route('/api/ai/engine', methods=['POST'])
def api_ai():
    msg = ((request.get_json(silent=True) or {}).get("message") or "").lower().strip()
    u = session.get('user', 'زائر')
    conn = get_db(); c = conn.cursor()
    if any(w in msg for w in ['نزاع', 'مشكلة', 'نصب', 'احتيال']):
        d = c.execute("SELECT COUNT(*) as n FROM escrows WHERE status='DISPUTED'").fetchone()["n"]
        reply = f"🚨 النزاعات المفتوحة: {d}\n💡 يمكنك رفع أدلة عبر صفحة الصفقة."
    elif 'رصيد' in msg:
        if session.get('user'):
            r = c.execute("SELECT balance FROM users WHERE username=?", (u,)).fetchone()
            reply = f"💰 رصيدك: {r['balance']:.2f}$"
        else: reply = "سجل الدخول"
    elif 'ثقة' in msg:
        reply = f"⭐ نقاطك: {compute_trust(u)}/1000" if session.get('user') else "سجل الدخول"
    elif 'مساعدة' in msg:
        reply = "🤖 اكتب: رصيدي / ثقتى / النزاعات"
    else:
        reply = f"أهلاً {u}. اكتب 'مساعدة'"
    conn.close()
    return jsonify({"reply": reply})

@app.route('/api/admin/stats')
@login_required
def api_stats():
    if not is_admin(): return jsonify({"status": "ERROR", "message": "مرفوض"})
    conn = get_db()
    u = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
    e = conn.execute("SELECT COUNT(*) as c FROM escrows").fetchone()["c"]
    t = conn.execute("SELECT * FROM treasury WHERE id=1").fetchone()
    conn.close()
    return jsonify({"status": "SUCCESS", "users": u, "escrows": e, "balance": t["balance"], "commission": t["total_commission"]})

@app.route('/api/admin/ban', methods=['POST'])
@login_required
def api_ban():
    if not is_admin(): return jsonify({"status": "ERROR", "message": "مرفوض"})
    t = (request.get_json(silent=True) or {}).get("target", "").strip()
    if t == MASTER_OWNER: return jsonify({"status": "ERROR", "message": "لا يمكن حظر المالك"})
    conn = get_db()
    conn.execute("UPDATE users SET status='BANNED' WHERE username=?", (t,))
    conn.close()
    return jsonify({"status": "SUCCESS", "message": f"تم حظر {t}"})

@app.route('/api/vault/unlock', methods=['POST'])
def api_vault_unlock():
    if session.get('user') != MASTER_OWNER:
        return jsonify({"status": "ERROR", "message": "مرفوض"})
    pin = (request.get_json(silent=True) or {}).get("pin", "")
    if pin == VAULT_PIN:
        session['vault_unlocked'] = True
        return jsonify({"status": "SUCCESS"})
    time.sleep(1)
    return jsonify({"status": "ERROR", "message": "رمز خطأ"})

@app.route('/api/vault/stats')
@login_required
def api_vault_stats():
    if not vault_unlocked(): return jsonify({"status": "ERROR", "message": "مقفلة"})
    conn = get_db()
    t = conn.execute("SELECT * FROM treasury WHERE id=1").fetchone()
    u = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
    conn.close()
    return jsonify({"status": "SUCCESS", "balance": t["balance"], "commission": t["total_commission"], "locked": t["total_locked"], "released": t["total_released"], "rate": t["commission_rate"], "users": u})

@app.route('/api/owner/login', methods=['POST'])
def api_owner_login():
    p = (request.get_json(silent=True) or {}).get("password", "")
    conn = get_db()
    r = conn.execute("SELECT * FROM users WHERE username=?", (MASTER_OWNER,)).fetchone()
    conn.close()
    if not r or not check_password_hash(r["password_hash"], p):
        time.sleep(1)
        return jsonify({"status": "ERROR", "message": "خاطئة"})
    session.clear(); session.permanent = True
    session['user'] = MASTER_OWNER
    session['role'] = 'OWNER'
    session['owner_verified'] = True
    return jsonify({"status": "SUCCESS"})

@app.route('/api/owner/change-password', methods=['POST'])
def api_owner_pwd():
    if not owner_verified(): return jsonify({"status": "ERROR", "message": "غير مصرح"})
    d = request.get_json(silent=True) or {}
    old, new = d.get("old", ""), d.get("new", "")
    ok, msg = valid_pass(new)
    if not ok: return jsonify({"status": "ERROR", "message": msg})
    conn = get_db()
    r = conn.execute("SELECT password_hash FROM users WHERE username=?", (MASTER_OWNER,)).fetchone()
    if not r or not check_password_hash(r["password_hash"], old):
        conn.close()
        return jsonify({"status": "ERROR", "message": "الكلمة الحالية خاطئة"})
    conn.execute("UPDATE users SET password_hash=? WHERE username=?", (generate_password_hash(new), MASTER_OWNER))
    conn.close()
    return jsonify({"status": "SUCCESS", "message": "تم التغيير"})

@app.route('/api/owner/change-pin', methods=['POST'])
def api_owner_pin():
    if not owner_verified(): return jsonify({"status": "ERROR", "message": "غير مصرح"})
    global VAULT_PIN
    d = request.get_json(silent=True) or {}
    old, new = d.get("old", ""), d.get("new", "")
    if not re.match(r'^\d{4,8}$', new):
        return jsonify({"status": "ERROR", "message": "PIN: 4-8 أرقام"})
    if old != VAULT_PIN:
        time.sleep(1)
        return jsonify({"status": "ERROR", "message": "PIN خاطئ"})
    VAULT_PIN = new
    try:
        with open('.vault_pin', 'w') as f: f.write(new)
    except: pass
    return jsonify({"status": "SUCCESS", "message": "تم تغيير PIN"})

HTML = r'''<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>منصة الضمان المالي الآمن</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Tahoma,sans-serif;background:#07090e;color:#f1f5f9;padding:10px;line-height:1.5}
.c{max-width:1000px;margin:auto;background:#111827;padding:15px;border-radius:12px;border:1px solid #1f2937}
.h{text-align:center;border-bottom:1px solid #1f2937;padding-bottom:12px;margin-bottom:15px;position:relative}
.logo{font-size:36px}
h2{color:#38bdf8;font-size:20px;margin:0 0 5px}
.b{color:#10b981;font-size:12px;background:#064e3b;padding:4px 10px;border-radius:20px;display:inline-block}
.s{position:absolute;top:5px;left:5px;width:30px;height:30px;background:#b45309;border-radius:50%;cursor:pointer;opacity:1;top:10px;left:10px;border:2px solid #fbbf24}
.g{display:flex;flex-direction:column;gap:15px}
@media(min-width:768px){.g{display:grid;grid-template-columns:1fr 1fr;gap:15px}}
.sec{background:#1f2937;padding:15px;border-radius:10px;border:1px solid #374151}
h3{margin:0 0 12px;color:#cbd5e1;font-size:15px;border-bottom:1px solid #374151;padding-bottom:8px}
.fg{margin-bottom:12px}
label{display:block;font-size:12px;color:#94a3b8;margin-bottom:4px}
input,select,textarea{width:100%;padding:11px;border-radius:8px;background:#0b0f19;color:#fff;border:1px solid #4b5563;font-size:14px;font-family:inherit}
input:focus,select:focus,textarea:focus{border-color:#38bdf8;outline:none}
button{width:100%;padding:11px;border-radius:8px;border:none;font-size:14px;font-weight:bold;cursor:pointer;margin-top:6px;font-family:inherit}
button:active{transform:scale(.98)}
.bp{background:#0284c7;color:#fff}.bs{background:#10b981;color:#fff}.bd{background:#dc2626;color:#fff}
.bw{background:#d97706;color:#fff}.bg{background:#4b5563;color:#fff}.bgold{background:#b45309;color:#fff}
.row{display:flex;justify-content:space-between;font-size:13px;background:#0b0f19;padding:10px;border-radius:6px;margin-bottom:8px}
.chat{background:#0b0f19;padding:10px;height:150px;overflow-y:scroll;border:1px solid #4b5563;border-radius:6px;margin-bottom:8px;font-size:13px}
.item{background:#0b0f19;padding:12px;margin-top:8px;border-radius:8px;border-right:4px solid #10b981;font-size:13px}
.item.locked{border-right-color:#f59e0b}.item.disputed{border-right-color:#dc2626}
.admin{background:#3d1a05;border:1px solid #b45309;display:none}
.ok{color:#4ade80;font-size:12px;margin-top:6px}.err{color:#f87171;font-size:12px;margin-top:6px}
.hide{display:none!important}
.tabs{display:flex;gap:5px;flex-wrap:wrap;margin-bottom:12px;border-bottom:1px solid #374151;padding-bottom:8px}
.tab{padding:8px 12px;background:#0b0f19;border:1px solid #374151;border-radius:6px;cursor:pointer;font-size:12px;color:#94a3b8}
.tab.on{background:#0284c7;color:#fff;border-color:#0284c7}
#toasts{position:fixed;top:15px;left:50%;transform:translateX(-50%);z-index:9999;width:90%;max-width:400px}
.toast{padding:12px 16px;border-radius:8px;margin-bottom:8px;color:#fff;font-weight:bold;font-size:13px}
.toast.s{background:#10b981}.toast.e{background:#dc2626}.toast.i{background:#0284c7}
</style>
</head>
<body>
<div id="toasts"></div>
<div class="c">
<div class="h">
<div class="logo">🛡️</div>
<h2>منصة الضمان المالي الآمن</h2>
<div class="b">Enterprise Escrow • EssamElkomy369</div>
<div class="s" onclick="location.href='/owner'"></div>
</div>
<div id="authView" class="g">
<div class="sec">
<h3>👤 دخول / حساب جديد</h3>
<div class="fg"><label>اسم المستخدم</label><input id="u" placeholder="3-30 حرف/رقم"></div>
<div class="fg"><label>كلمة المرور</label><input type="password" id="p" placeholder="8+ أحرف ورقم"></div>
<button class="bp" onclick="reg()">تسجيل حساب جديد</button>
<button class="bs" onclick="login()">تسجيل الدخول</button>
</div>
<div class="sec">
<h3>💰 محفظتك</h3>
<div class="row"><span>المستخدم:</span><b id="who" style="color:#38bdf8">غير مسجل</b></div>
<div class="row"><span>الرصيد:</span><b id="bal" style="color:#10b981">0.00 $</b></div>
<div class="row"><span>⭐ الثقة:</span><b id="trust" style="color:#fbbf24">--</b></div>
</div>
</div>
<div id="mainView" class="hide">
<div class="tabs">
<div class="tab on" onclick="tab('e')" id="t_e">🤝 الصفقات</div>
<div class="tab" onclick="tab('w')" id="t_w">💰 المحفظة</div>
<div class="tab" onclick="tab('n')" id="t_n">🔔 الإشعارات</div>
<div class="tab" onclick="tab('k')" id="t_k">📋 KYC</div>
<div class="tab" onclick="tab('p')" id="t_p">👤 حسابي</div>
<div class="tab hide" onclick="tab('a')" id="t_a">⚙️ الإدارة</div>
</div>
<div id="v_e">
<div class="sec"><h3>🤝 الصفقات</h3><div id="eList">جاري التحميل...</div></div>
<div class="sec"><h3>➕ إنشاء صفقة</h3>
<div class="fg"><label>اسم البائع</label><input id="sel" placeholder="اسم البائع"></div>
<div class="fg"><label>المبلغ</label><input type="number" id="amt" step="0.01" placeholder="0.00"></div>
<button class="bs" onclick="create()">🔒 إنشاء وقفل المبلغ</button>
</div>
<div class="sec"><h3>🤖 وكيل الأمان</h3>
<div class="chat" id="aiChat">مرحباً. اسألني عن رصيدك أو ثقتك.</div>
<input id="aiIn" placeholder="اكتب رسالتك...">
<button class="bp" onclick="aiAsk()">إرسال</button></div>
</div>
<div id="v_w" class="hide">
<div class="sec"><h3>💰 المحفظة</h3>
<div class="row"><span>الرصيد:</span><b id="bal2" style="color:#10b981">0.00 $</b></div>
<div class="fg"><label>إيداع</label><input type="number" id="dep" step="0.01" placeholder="المبلغ"></div>
<button class="bs" onclick="deposit()">إيداع</button>
<a href="/api/export/pdf" style="text-decoration:none;display:block"><button class="bp" style="margin-top:8px">📄 تصدير PDF</button></a>
<a href="/api/export/csv" style="text-decoration:none;display:block"><button class="bg" style="margin-top:6px">📥 تصدير CSV</button></a>
</div>
<div class="sec"><h3>📜 المعاملات</h3><div id="txList">جاري التحميل...</div></div>
</div>
<div id="v_n" class="hide">
<div class="sec"><h3>🔔 الإشعارات</h3><div id="notifList">جاري التحميل...</div></div>
</div>
<div id="v_p" class="hide">
<div class="sec"><h3>👤 الملف الشخصي</h3>
<div class="row"><span>الاسم:</span><b id="pUser"></b></div>
<div class="row"><span>الدور:</span><b id="pRole"></b></div>
<div class="row"><span>الرصيد:</span><b id="pBal"></b></div>
<div class="row"><span>KYC:</span><b id="pKyc"></b></div>
<div class="row"><span>⭐ نقاط الثقة:</span><b id="pTrust" style="color:#10b981"></b></div>
<div class="row"><span>🎁 كود الإحالة:</span><b id="pRef" style="color:#fbbf24;font-family:monospace"></b></div>
<div class="row"><span>📧 البريد:</span><b id="pEmail" style="color:#38bdf8">--</b></div>
</div>
<div class="sec">
<h3>📧 حفظ البريد للإشعارات</h3>
<form method="POST" action="/save-email-form">
<div class="fg"><label>بريدك الإلكتروني</label><input name="email" type="email" placeholder="you@example.com" required></div>
<button class="bs" type="submit">💾 حفظ البريد</button>
</form>
</div>
<div class="sec"><h3>🔑 تغيير كلمة المرور</h3>
<div class="fg"><label>الحالية</label><input type="password" id="oldP"></div>
<div class="fg"><label>الجديدة</label><input type="password" id="newP"></div>
<button class="bs" onclick="changePwd()">تحديث</button>
</div>
</div>
<div id="v_k" class="hide">
<div class="sec"><h3>📋 التحقق من الهوية (KYC)</h3>
<div class="row"><span>الحالة:</span><b id="kStat" style="color:#fbbf24">NONE</b></div>
<div class="fg"><label>الاسم الكامل</label><input id="kName" placeholder="كما في البطاقة"></div>
<div class="fg"><label>رقم الهوية</label><input id="kId" placeholder="رقم البطاقة/الباسبور"></div>
<button class="bs" onclick="kycSubmit()">📤 إرسال طلب KYC</button>
</div>
<div class="sec"><h3>ℹ️ لماذا KYC؟</h3>
<p style="color:#9ca3af;font-size:13px;line-height:1.8">• يمنحك ثقة أعلى (+200 نقطة)<br>• يفتح حد صفقات أكبر<br>• يحمي المنصة من الاحتيال<br>• مطلوب قانونياً للمنصات المالية</p>
</div>
</div>
<div id="v_a" class="hide">
<div class="sec admin" style="display:block">
<h3>⚙️ لوحة المسؤول</h3>
<a href="/vault" style="display:block;text-decoration:none;margin-bottom:10px"><button class="bgold">🔐 الخزنة الخاصة</button></a>
<div class="fg"><input id="banT" placeholder="اسم المستخدم"><button class="bd" onclick="ban()">حظر</button></div>
<button class="bg" onclick="kycList()">📋 طلبات KYC</button>
<button class="bg" onclick="stats()">📊 إحصائيات</button>
</div>
</div>
<button class="bd" style="margin-top:15px" onclick="logout()">🚪 تسجيل الخروج</button>
</div>
</div>
<script>
let me="",role="";
function toast(m,t='i'){let d=document.createElement('div');d.className='toast '+t;d.innerText=m;document.getElementById('toasts').appendChild(d);setTimeout(()=>d.remove(),3500);}
function api(u,m='POST',b={}){return fetch(u,{method:m,headers:{'Content-Type':'application/json'},body:m==='POST'?JSON.stringify(b):undefined}).then(r=>r.json());}
function show(id){document.querySelectorAll('[id^=v_]').forEach(x=>x.classList.add('hide'));document.getElementById('v_'+id).classList.remove('hide');}
function tab(id){show(id);document.querySelectorAll('.tab').forEach(x=>x.classList.remove('on'));document.getElementById('t_'+id).classList.add('on');
if(id==='n')loadNotifs();if(id==='w')loadWallet();if(id==='p')loadProfile();if(id==='k')loadKyc();}
function reg(){let u=document.getElementById('u').value.trim(),p=document.getElementById('p').value;
if(!u||!p)return toast('املأ الحقول','e');
api('/api/register','POST',{username:u,password:p}).then(d=>toast(d.message,d.status==='SUCCESS'?'s':'e'));}
function login(){let u=document.getElementById('u').value.trim(),p=document.getElementById('p').value;
api('/api/login','POST',{username:u,password:p}).then(d=>{
if(d.status!=='SUCCESS')return toast(d.message,'e');
me=u;role=d.role;document.getElementById('who').innerText=u;document.getElementById('bal').innerText=d.balance.toFixed(2)+' $';document.getElementById('trust').innerText=d.trust;
document.getElementById('authView').classList.add('hide');document.getElementById('mainView').classList.remove('hide');
if(d.role==='OWNER')document.getElementById('t_a').classList.remove('hide');
toast('مرحباً '+u,'s');
function doKyc(){
    var n = document.getElementById('kName').value.trim();
    var i = document.getElementById('kId').value.trim();
    if(!n || !i){ alert('املأ الحقول'); return; }
    fetch('/api/kyc/submit', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({full_name:n, id_number:i})
    }).then(function(r){return r.json();}).then(function(d){
        alert(d.message);
        if(d.status==='SUCCESS'){location.reload();}
    }).catch(function(e){alert('خطأ: '+e);});
}


function kycList(){
    fetch('/api/admin/kyc/list').then(r=>r.json()).then(d=>{
        if(d.status!=='SUCCESS') return alert(d.message);
        if(!d.submissions.length) return alert('لا طلبات معلقة');
        d.submissions.forEach(function(s){
            var dec = prompt('طلب KYC من ' + s.username + '\nالاسم: ' + s.full_name + '\nالرقم: ' + s.id_number + '\n\nاكتب APPROVED أو REJECTED:');
            if(dec === 'APPROVED' || dec === 'REJECTED'){
                fetch('/api/admin/kyc/review', {
                    method: 'POST',
                    headers: {'Content-Type':'application/json'},
                    body: JSON.stringify({id: s.id, decision: dec})
                }).then(r=>r.json()).then(function(x){ alert(x.message); });
            }
        });
    });
}


function saveEmail(){
    var e = document.getElementById('emailInput').value.trim();
    if(!e || e.indexOf('@') === -1){ alert('أدخل بريد صالح'); return; }
    fetch('/api/save-email', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({email: e})
    }).then(function(r){return r.json();}).then(function(d){
        var msg = document.getElementById('emailMsg');
        msg.innerText = d.message;
        msg.style.color = d.status === 'SUCCESS' ? '#4ade80' : '#f87171';
        if(d.status === 'SUCCESS'){ document.getElementById('pEmail').innerText = e; }
    });
}

loadEscrows();});}
function logout(){api('/api/logout','POST',{}).then(()=>location.reload());}
function loadEscrows(){fetch('/api/escrows').then(r=>r.json()).then(d=>{
let b=document.getElementById('eList');b.innerHTML='';
if(!d.escrows.length){b.innerHTML="<p style='color:#6b7280;font-size:13px'>لا صفقات.</p>";return;}
d.escrows.forEach(e=>{
let c=e.status==='LOCKED_SECURE'?'locked':e.status==='DISPUTED'?'disputed':'';
let a='';
if(e.status==='LOCKED_SECURE'&&e.buyer===me)a+='<button class="bs" style="padding:6px;font-size:11px;width:auto;margin:3px" onclick="release('+e.id+')">✅ تحرير</button>';
if(e.status==='LOCKED_SECURE'&&(e.buyer===me||e.seller===me))a+='<button class="bw" style="padding:6px;font-size:11px;width:auto;margin:3px" onclick="dispute('+e.id+')">⚠️ نزاع</button>';
if(e.buyer&&(e.buyer===me||e.seller===me))a+='<a href="/escrow/'+e.id+'/chat" style="text-decoration:none"><button class="bp" style="padding:6px;font-size:11px;width:auto;margin:3px">💬 شات</button></a>';
if(e.seller!==me)a+='<a href="/u/'+e.seller+'" style="text-decoration:none"><button class="bg" style="padding:6px;font-size:11px;width:auto;margin:3px">👤 '+e.seller+'</button></a>';
if(e.buyer&&e.buyer!==me)a+='<a href="/u/'+e.buyer+'" style="text-decoration:none"><button class="bg" style="padding:6px;font-size:11px;width:auto;margin:3px">👤 '+e.buyer+'</button></a>';
if(e.status==='LOCKED_SECURE'&&e.seller===me)a+='<a href="/escrow/'+e.id+'/milestones" style="text-decoration:none"><button class="bw" style="padding:6px;font-size:11px;width:auto;margin:3px">📋 مراحل</button></a>';
if(e.status==='RELEASED'&&(e.buyer===me||e.seller===me))a+='<a href="/escrow/'+e.id+'/review" style="text-decoration:none"><button class="bg" style="padding:6px;font-size:11px;width:auto;margin:3px">⭐ قيّم</button></a>';
b.innerHTML+='<div class="item '+c+'"><b>#'+e.id+'</b> | بائع: <b>'+e.seller+'</b> | مشتري: <b>'+(e.buyer||'—')+'</b><br>المبلغ: <b>'+e.amount+'</b> | حالة: <b>'+e.status+'</b><div>'+a+'</div></div>';});});}
function create(){let s=document.getElementById('sel').value.trim(),a=parseFloat(document.getElementById('amt').value);
if(!s||isNaN(a)||a<=0)return toast('بيانات غير صالحة','e');
api('/api/escrow/create','POST',{seller:s,amount:a}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');if(d.status==='SUCCESS')loadEscrows();});}
function release(id){if(!confirm('تأكيد التحرير؟'))return;
api('/api/escrow/release','POST',{escrow_id:id}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');loadEscrows();});}
function dispute(id){let r=prompt('سبب النزاع:');if(!r)return;
api('/api/escrow/dispute','POST',{escrow_id:id,reason:r}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');loadEscrows();});}
function loadWallet(){api('/api/me','GET').then(d=>{if(d.status==='SUCCESS')document.getElementById('bal2').innerText=d.user.balance.toFixed(2)+' $';});
fetch('/api/transactions').then(r=>r.json()).then(d=>{
let b=document.getElementById('txList');b.innerHTML='';
if(!d.transactions||!d.transactions.length){b.innerHTML="<p style='color:#6b7280;font-size:13px'>لا معاملات.</p>";return;}
d.transactions.forEach(t=>{b.innerHTML+='<div class="item" style="border-right-color:#0284c7;font-size:12px"><b>'+t.type+'</b>: '+t.amount+'$ | '+(t.note||'')+'</div>';});});}
function deposit(){let a=parseFloat(document.getElementById('dep').value);if(isNaN(a)||a<=0)return toast('مبلغ غير صالح','e');
api('/api/wallet/deposit','POST',{amount:a}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');if(d.status==='SUCCESS')loadWallet();});}
function loadNotifs(){fetch('/api/notifications').then(r=>r.json()).then(d=>{
let b=document.getElementById('notifList');b.innerHTML='';
if(!d.notifications||!d.notifications.length){b.innerHTML="<p style='color:#6b7280;font-size:13px'>لا إشعارات.</p>";return;}
d.notifications.forEach(n=>{b.innerHTML+='<div class="item"><b>'+n.title+'</b><br>'+(n.body||'')+'</div>';});});}
function loadProfile(){api('/api/me','GET').then(d=>{if(d.status!=='SUCCESS')return;
document.getElementById('pUser').innerText=d.user.username;document.getElementById('pRole').innerText=d.user.role;
document.getElementById('pBal').innerText=d.user.balance.toFixed(2)+' $';document.getElementById('pKyc').innerText=d.user.kyc_status;
document.getElementById('pTrust').innerText=(d.user.trust_score||100)+'/1000';document.getElementById('pRef').innerText=d.user.referral_code||'--';});}
function changePwd(){let o=document.getElementById('oldP').value,n=document.getElementById('newP').value;
api('/api/change-password','POST',{old:o,new:n}).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');if(d.status==='SUCCESS'){document.getElementById('oldP').value='';document.getElementById('newP').value='';}});}
function ban(){let t=document.getElementById('banT').value.trim();if(!t)return;
api('/api/admin/ban','POST',{target:t}).then(d=>toast(d.message,d.status==='SUCCESS'?'s':'e'));}
function stats(){fetch('/api/admin/stats').then(r=>r.json()).then(d=>{if(d.status!=='SUCCESS')return toast(d.message,'e');
alert('👥 المستخدمون: '+d.users+'\n📋 الصفقات: '+d.escrows+'\n💰 الخزنة: '+d.balance+'$\n📈 العمولات: '+d.commission+'$');});}
function aiAsk(){let m=document.getElementById('aiIn').value.trim();if(!m)return;
let c=document.getElementById('aiChat');c.innerHTML+='<br><b>أنت:</b> '+m;
api('/api/ai/engine','POST',{message:m}).then(d=>{c.innerHTML+='<br><span style="color:#38bdf8"><b>الوكيل:</b> '+d.reply+'</span>';c.scrollTop=c.scrollHeight;document.getElementById('aiIn').value='';});}
function loadKyc(){fetch('/api/kyc/status').then(r=>r.json()).then(d=>{
if(d.status==='SUCCESS'&&d.kyc){document.getElementById('kStat').innerText=d.kyc.status;}
else{document.getElementById('kStat').innerText='NONE';}});}
function kycSubmit(){let n=document.getElementById('kName').value.trim(),i=document.getElementById('kId').value.trim();
if(!n||!i)return toast('املأ الحقول','e');
fetch('/api/kyc/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({full_name:n,id_number:i})})
.then(r=>r.json()).then(d=>{toast(d.message,d.status==='SUCCESS'?'s':'e');if(d.status==='SUCCESS')loadKyc();});}
loadEscrows();

document.addEventListener('DOMContentLoaded', function(){
    var btn = document.getElementById('kycBtn');
    if(btn){
        btn.addEventListener('click', function(){
            var n = (document.getElementById('kName')||{}).value || '';
            var i = (document.getElementById('kId')||{}).value || '';
            n = n.trim(); i = i.trim();
            if(!n || !i){ alert('املأ الاسم ورقم الهوية'); return; }
            fetch('/api/kyc/submit', {
                method: 'POST',
                headers: {'Content-Type':'application/json'},
                body: JSON.stringify({full_name:n, id_number:i})
            }).then(function(r){ return r.json(); })
              .then(function(d){
                  alert(d.message);
                  if(d.status==='SUCCESS'){ location.reload(); }
              })
              .catch(function(e){ alert('خطأ: ' + e); });
        });
    }
});

if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js').catch(()=>{});}
</script>
</body></html>'''

OWNER_HTML = r'''<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>🔐 المالك</title>
<style>
body{font-family:Tahoma;background:#07090e;color:#f1f5f9;padding:20px;margin:0}
.c{max-width:500px;margin:30px auto;background:#111827;padding:25px;border-radius:14px;border:1px solid #b45309}
h1{color:#fbbf24;text-align:center;font-size:22px;margin-bottom:15px}
.tabs{display:flex;gap:5px;margin-bottom:15px}
.tab{flex:1;padding:10px;background:#0b0f19;border:1px solid #374151;border-radius:8px;text-align:center;cursor:pointer;color:#94a3b8}
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
<div id="codeBox" style="display:none">
<label>رمز 2FA</label>
<input type="text" id="code" inputmode="numeric" maxlength="6" placeholder="000000">
</div>
<button onclick="ol()">🔓 دخول</button>
<p id="m1" class="err"></p>
</div>
<a href="/">← العودة</a>
</div>
<div id="panelView" class="hide">
<div class="tabs">
<div class="tab on" id="tb1" onclick="st('pwd')">🔑 كلمة المرور</div>
<div class="tab" id="tb2" onclick="st('pin')">🔒 PIN الخزنة</div>
<div class="tab" id="tb3" onclick="st('2fa')">🔐 2FA</div>
</div>
<div id="tpwd">
<div class="s">
<label>الحالية</label><input type="password" id="op">
<label>الجديدة</label><input type="password" id="np">
<label>تأكيد</label><input type="password" id="np2">
<button onclick="cp()">💾 حفظ</button>
<p id="m2"></p>
</div></div>
<div id="t2fa" class="hide">
<div class="s">
<p style="color:#9ca3af;font-size:13px">حماية بخطوتين لحساب المالك</p>
<p style="margin:10px 0">الحالة: <b id="twofaStatus" style="color:#fbbf24">--</b></p>
<button id="setupBtn" onclick="setup2fa()">⚙️ إعداد 2FA</button>
<div id="twofaSetup" style="display:none;margin-top:12px;padding-top:12px;border-top:1px solid #374151">
<p style="font-size:12px;color:#9ca3af">امسح QR بتطبيق Google Authenticator:</p>
<img id="qrImg" style="display:none;width:180px;margin:8px auto">
<p style="font-size:12px;color:#9ca3af">أو أدخل يدوياً:</p>
<p style="font-family:monospace;font-size:11px;background:#030712;padding:8px;border-radius:6px;word-break:break-all" id="secretTxt">--</p>
<p style="font-size:12px;color:#f87171;margin-top:8px">🔑 احفظ الرمز الاحتياطي:</p>
<p style="font-family:monospace;font-size:11px;background:#7c2d12;padding:8px;border-radius:6px" id="backupTxt">--</p>
<label>أدخل الرمز المكوّن من 6 أرقام:</label>
<input type="text" id="setupCode" inputmode="numeric" maxlength="6" placeholder="000000">
<button onclick="enable2fa()">✅ تفعيل</button>
</div>
</div>
</div>
<div id="tpin" class="hide">
<div class="s">
<label>PIN الحالي</label><input type="password" id="opn" inputmode="numeric">
<label>PIN الجديد</label><input type="password" id="npn" inputmode="numeric">
<label>تأكيد PIN</label><input type="password" id="npn2" inputmode="numeric">
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
document.getElementById('tpin').classList.toggle('hide',t!=='pin');
let t2=document.getElementById('t2fa');if(t2)t2.classList.toggle('hide',t!=='2fa');
let tb3=document.getElementById('tb3');if(tb3&&t==='2fa'){document.querySelectorAll('.tab').forEach(x=>x.classList.remove('on'));tb3.classList.add('on');load2faStatus();}}
function ol(){let p=document.getElementById('p').value;if(!p)return;
fetch('/api/owner/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})})
.then(r=>r.json()).then(d=>{
if(d.status==='SUCCESS'){document.getElementById('loginView').classList.add('hide');document.getElementById('panelView').classList.remove('hide');load2faStatus();}
else if(d.status==='NEED_2FA'){document.getElementById('codeBox').style.display='block';document.getElementById('m1').innerText='أدخل رمز 2FA';}
else document.getElementById('m1').innerText=d.message;});}

function load2faStatus(){fetch('/api/owner/2fa/status').then(r=>r.json()).then(d=>{
let s=document.getElementById('twofaStatus');if(s)s.innerText=d.enabled?'✅ مفعّل':'⚠️ معطّل';
let b=document.getElementById('setupBtn');if(b)b.style.display=d.enabled?'none':'block';});}

function setup2fa(){fetch('/api/owner/2fa/setup',{method:'POST',headers:{'Content-Type':'application/json'}}).then(r=>r.json()).then(d=>{
if(d.status!=='SUCCESS')return alert(d.message);
document.getElementById('twofaSetup').style.display='block';
if(d.qr){document.getElementById('qrImg').src=d.qr;document.getElementById('qrImg').style.display='block';}
document.getElementById('secretTxt').innerText=d.secret;
document.getElementById('backupTxt').innerText=d.backup;});}

function enable2fa(){let c=document.getElementById('setupCode').value.trim();if(!c)return alert('أدخل الرمز');
fetch('/api/owner/2fa/enable',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:c})}).then(r=>r.json()).then(d=>{
alert(d.message);if(d.status==='SUCCESS'){document.getElementById('twofaSetup').style.display='none';load2faStatus();}});}
function cp(){let o=document.getElementById('op').value,n=document.getElementById('np').value,n2=document.getElementById('np2').value;
if(!o||!n)return document.getElementById('m2').innerText='املأ الحقول';
if(n!==n2)return document.getElementById('m2').innerText='غير متطابقتين';
fetch('/api/owner/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old:o,new:n})})
.then(r=>r.json()).then(d=>{document.getElementById('m2').className=d.status==='SUCCESS'?'ok':'err';document.getElementById('m2').innerText=d.message;
if(d.status==='SUCCESS'){document.getElementById('op').value='';document.getElementById('np').value='';document.getElementById('np2').value='';}});}
function cpn(){let o=document.getElementById('opn').value,n=document.getElementById('npn').value,n2=document.getElementById('npn2').value;
if(!o||!n)return document.getElementById('m3').innerText='املأ الحقول';
if(n!==n2)return document.getElementById('m3').innerText='غير متطابقين';
fetch('/api/owner/change-pin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old:o,new:n})})
.then(r=>r.json()).then(d=>{document.getElementById('m3').className=d.status==='SUCCESS'?'ok':'err';document.getElementById('m3').innerText=d.message;
if(d.status==='SUCCESS'){document.getElementById('opn').value='';document.getElementById('npn').value='';document.getElementById('npn2').value='';}});}
</script></body></html>'''

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
.panel{background:#111827;padding:18px;border-radius:10px;border:1px solid #374151}
.panel h3{color:#fbbf24;margin-top:0}
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
<div class="panel"><h3>⚙️ الإعدادات</h3>
<p style="color:#9ca3af;font-size:13px">العمولة الحالية: <b id="rate" style="color:#fbbf24"></b>%</p>
</div>
</div>
</div>
<script>
function unlock(){let p=document.getElementById('pin').value;
fetch('/api/vault/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin:p})})
.then(r=>r.json()).then(d=>{if(d.status==='SUCCESS'){document.getElementById('pinGate').classList.add('hide');document.getElementById('content').classList.remove('hide');load();}
else document.getElementById('pm').innerText=d.message;});}
function load(){fetch('/api/vault/stats').then(r=>r.json()).then(d=>{
if(d.status!=='SUCCESS')return;
document.getElementById('s1').innerText=d.balance.toFixed(2)+'$';
document.getElementById('s2').innerText=d.commission.toFixed(2)+'$';
document.getElementById('s3').innerText=d.locked.toFixed(2)+'$';
document.getElementById('s4').innerText=d.released.toFixed(2)+'$';
document.getElementById('s5').innerText=d.users;
document.getElementById('rate').innerText=d.rate;});}
</script></body></html>'''


@app.route('/manifest.json')
def pwa_manifest():
    from flask import Response
    import json
    m = {"name":"Escrow Platform","short_name":"Escrow","start_url":"/","display":"standalone","background_color":"#07090e","theme_color":"#0284c7","orientation":"portrait","lang":"ar","dir":"rtl"}
    return Response(json.dumps(m, ensure_ascii=False), mimetype="application/manifest+json")

@app.route('/sw.js')
def pwa_sw():
    from flask import Response
    sw = "self.addEventListener('install',e=>self.skipWaiting());self.addEventListener('activate',e=>clients.claim());self.addEventListener('fetch',e=>{if(e.request.method!=='GET')return;e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)))});"
    return Response(sw, mimetype="application/javascript")

@app.route('/')
def index(): return render_template_string(HTML)

@app.route('/owner')
def owner_page(): return render_template_string(OWNER_HTML)

@app.route('/vault')
def vault_page():
    if session.get('user') != MASTER_OWNER:
        return "<h1 style='font-family:Tahoma;color:#f87171;text-align:center;padding:50px'>🚫 مرفوض</h1>", 403
    return render_template_string(VAULT_HTML)

@app.route('/api/owner/2fa/setup', methods=['POST'])
def api_2fa_setup():
    if not owner_verified():
        return jsonify({"status": "ERROR", "message": "غير مصرح"})
    conn = get_db()
    existing = conn.execute("SELECT * FROM twofa WHERE username=?", (MASTER_OWNER,)).fetchone()
    if existing and existing['enabled']:
        conn.close()
        return jsonify({"status": "ERROR", "message": "2FA مفعّل مسبقاً"})
    secret = pyotp.random_base32()
    backup = secrets.token_hex(8).upper()
    if existing:
        conn.execute("UPDATE twofa SET secret=?, backup_code=?, enabled=0 WHERE username=?", (secret, backup, MASTER_OWNER))
    else:
        conn.execute("INSERT INTO twofa (username, secret, backup_code, enabled) VALUES (?, ?, ?, 0)", (MASTER_OWNER, secret, backup))
    conn.commit()
    conn.close()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name="EssamElkomy369", issuer_name="Escrow-Platform")
    qr_b64 = ""
    try:
        import qrcode
        from io import BytesIO
        qr = qrcode.make(uri)
        buf = BytesIO()
        qr.save(buf, format='PNG')
        qr_b64 = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except: pass
    return jsonify({"status": "SUCCESS", "secret": secret, "backup": backup, "qr": qr_b64})

@app.route('/api/owner/2fa/enable', methods=['POST'])
def api_2fa_enable():
    if not owner_verified():
        return jsonify({"status": "ERROR", "message": "غير مصرح"})
    code = (request.get_json(silent=True) or {}).get("code", "").strip()
    conn = get_db()
    r = conn.execute("SELECT * FROM twofa WHERE username=?", (MASTER_OWNER,)).fetchone()
    if not r:
        conn.close()
        return jsonify({"status": "ERROR", "message": "ابدأ الإعداد أولاً"})
    totp = pyotp.TOTP(r['secret'])
    if totp.verify(code, valid_window=1):
        conn.execute("UPDATE twofa SET enabled=1 WHERE username=?", (MASTER_OWNER,))
        conn.commit()
        conn.close()
        return jsonify({"status": "SUCCESS", "message": "✅ تم تفعيل 2FA!"})
    conn.close()
    return jsonify({"status": "ERROR", "message": "❌ رمز خاطئ"})

@app.route('/api/owner/2fa/verify', methods=['POST'])
def api_2fa_verify():
    d = request.get_json(silent=True) or {}
    p = d.get("password", "")
    code = d.get("code", "").strip()
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE username=?", (MASTER_OWNER,)).fetchone()
    t = conn.execute("SELECT * FROM twofa WHERE username=?", (MASTER_OWNER,)).fetchone()
    conn.close()
    if not u or not check_password_hash(u['password_hash'], p):
        time.sleep(1)
        return jsonify({"status": "ERROR", "message": "كلمة المرور خاطئة"})
    if t and t['enabled']:
        if not code:
            return jsonify({"status": "NEED_2FA", "message": "أدخل رمز 2FA"})
        totp = pyotp.TOTP(t['secret'])
        if not totp.verify(code, valid_window=1) and code.upper() != t['backup_code']:
            return jsonify({"status": "ERROR", "message": "رمز 2FA خاطئ"})
    session.clear(); session.permanent = True
    session['user'] = MASTER_OWNER
    session['role'] = 'OWNER'
    session['owner_verified'] = True
    return jsonify({"status": "SUCCESS"})

@app.route('/api/owner/2fa/status')
def api_2fa_status():
    if session.get('user') != MASTER_OWNER:
        return jsonify({"status": "ERROR", "message": "غير مصرح"})
    conn = get_db()
    r = conn.execute("SELECT enabled FROM twofa WHERE username=?", (MASTER_OWNER,)).fetchone()
    conn.close()
    return jsonify({"status": "SUCCESS", "enabled": bool(r['enabled']) if r else False})
@app.route('/api/escrow/<int:eid>/evidence', methods=['GET'])
@login_required
def api_get_evidence(eid):
    conn = get_db()
    e = conn.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
    if not e or session['user'] not in (e['seller'], e['buyer']):
        conn.close(); return jsonify({"status":"ERROR","message":"غير مخول"})
    rows = conn.execute("SELECT * FROM evidence WHERE escrow_id=? ORDER BY id DESC", (eid,)).fetchall()
    conn.close()
    return jsonify({"status":"SUCCESS","evidence":[dict(r) for r in rows]})

@app.route('/api/escrow/<int:eid>/evidence', methods=['POST'])
@login_required
def api_add_evidence(eid):
    d = request.get_json(silent=True) or {}
    content = (d.get("content") or "").strip()[:50000]
    note = (d.get("note") or "").strip()[:300]
    if not content: return jsonify({"status":"ERROR","message":"المحتوى مطلوب"})
    conn = get_db()
    e = conn.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
    if not e or session['user'] not in (e['seller'], e['buyer']):
        conn.close(); return jsonify({"status":"ERROR","message":"غير مخول"})
    conn.execute("INSERT INTO evidence (escrow_id, uploader, content, note) VALUES (?,?,?,?)", (eid, session['user'], content, note))
    conn.close()
    return jsonify({"status":"SUCCESS","message":"تم رفع الدليل"})

@app.route('/api/kyc/status')
@login_required
def api_kyc_status():
    conn = get_db()
    r = conn.execute("SELECT * FROM kyc_submissions WHERE username=? ORDER BY id DESC LIMIT 1", (session['user'],)).fetchone()
    conn.close()
    return jsonify({"status": "SUCCESS", "kyc": dict(r) if r else None})


@app.route('/api/kyc/submit', methods=['POST'])
@login_required
def api_kyc_submit():
    d = request.get_json(silent=True) or {}
    fn = (d.get("full_name") or "").strip()[:100]
    idn = (d.get("id_number") or "").strip()[:50]
    if not fn or not idn:
        return jsonify({"status": "ERROR", "message": "الاسم ورقم الهوية مطلوبان"})
    conn = get_db()
    if conn.execute("SELECT 1 FROM kyc_submissions WHERE username=? AND status='PENDING'", (session['user'],)).fetchone():
        conn.close()
        return jsonify({"status": "ERROR", "message": "لديك طلب قيد المراجعة"})
    conn.execute("INSERT INTO kyc_submissions (username, full_name, id_number) VALUES (?,?,?)", (session['user'], fn, idn))
    conn.execute("UPDATE users SET kyc_status='PENDING' WHERE username=?", (session['user'],))
    conn.commit()
    conn.close()
    return jsonify({"status": "SUCCESS", "message": "تم إرسال طلب KYC"})




@app.route('/api/admin/kyc/list')
@login_required
def api_kyc_list():
    if not is_admin():
        return jsonify({"status": "ERROR", "message": "مرفوض"})
    conn = get_db()
    rows = conn.execute("SELECT * FROM kyc_submissions WHERE status='PENDING' ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify({"status": "SUCCESS", "submissions": [dict(r) for r in rows]})


@app.route('/api/admin/kyc/review', methods=['POST'])
@login_required
def api_kyc_review():
    if not is_admin():
        return jsonify({"status": "ERROR", "message": "مرفوض"})
    d = request.get_json(silent=True) or {}
    sid = d.get("id")
    dec = d.get("decision")
    if dec not in ('APPROVED', 'REJECTED'):
        return jsonify({"status": "ERROR", "message": "قرار غير صالح"})
    conn = get_db()
    r = conn.execute("SELECT * FROM kyc_submissions WHERE id=?", (sid,)).fetchone()
    if not r:
        conn.close()
        return jsonify({"status": "ERROR", "message": "الطلب غير موجود"})
    conn.execute("UPDATE kyc_submissions SET status=? WHERE id=?", (dec, sid))
    conn.execute("UPDATE users SET kyc_status=? WHERE username=?", (dec, r['username']))
    conn.commit()
    conn.close()
    return jsonify({"status": "SUCCESS", "message": f"تم {dec}"})



EVIDENCE_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>📎 الأدلة - صفقة #{eid}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Tahoma,sans-serif;background:#07090e;color:#f1f5f9;padding:15px}
.c{max-width:700px;margin:auto;background:#111827;padding:20px;border-radius:12px;border:1px solid #1f2937}
h1{color:#38bdf8;text-align:center;font-size:20px;margin-bottom:5px}
.badge{text-align:center;color:#10b981;font-size:12px;margin-bottom:20px}
.sec{background:#1f2937;padding:15px;border-radius:10px;border:1px solid #374151;margin-bottom:12px}
.sec h3{color:#cbd5e1;margin-bottom:12px;font-size:15px;border-bottom:1px solid #374151;padding-bottom:8px}
label{display:block;color:#94a3b8;font-size:12px;margin:8px 0 4px}
input,textarea{width:100%;padding:11px;background:#0b0f19;color:#fff;border:1px solid #4b5563;border-radius:8px;font-size:14px;font-family:inherit}
textarea{min-height:80px;resize:vertical}
button{width:100%;padding:12px;background:#10b981;color:#fff;border:none;border-radius:8px;font-weight:bold;font-size:14px;cursor:pointer;margin-top:10px}
.item{background:#0b0f19;padding:12px;margin-top:10px;border-radius:8px;border-right:4px solid #38bdf8;font-size:13px}
.item b{color:#38bdf8}
.time{color:#6b7280;font-size:11px;margin-top:5px}
.back{display:block;text-align:center;color:#38bdf8;text-decoration:none;margin-top:15px;font-size:13px}
.empty{color:#6b7280;font-size:13px;text-align:center;padding:15px}
</style>
</head>
<body>
<div class="c">
<h1>📎 أدلة الصفقة #{eid}</h1>
<div class="badge">صفقة بين: {seller} → {buyer}</div>

<div class="sec">
<h3>📤 رفع دليل جديد</h3>
<form method="POST" action="/escrow/{eid}/evidence/add">
<label>المحتوى (نص أو رابط صورة)</label>
<textarea name="content" required placeholder="اكتب تفاصيل الدليل أو الصق رابط صورة"></textarea>
<label>ملاحظة (اختياري)</label>
<input type="text" name="note" placeholder="مثال: صورة المنتج قبل الشحن">
<button type="submit">📤 رفع الدليل</button>
</form>
</div>

<div class="sec">
<h3>📋 الأدلة المرفوعة ({count})</h3>
{evidence_html}
</div>

<a href="/" class="back">← العودة للمنصة</a>
</div>
</body>
</html>
"""


@app.route('/escrow/<int:eid>/evidence')
@login_required
def escrow_evidence_page(eid):
    conn = get_db()
    e = conn.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
    if not e or session['user'] not in (e['seller'], e['buyer']):
        conn.close()
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>🚫 غير مخول</h1>"
    rows = conn.execute("SELECT * FROM evidence WHERE escrow_id=? ORDER BY id DESC", (eid,)).fetchall()
    conn.close()
    if rows:
        ev = ""
        for r in rows:
            ev += f"<div class='item'><b>{r['uploader']}:</b> {r['content']}"
            if r['note']:
                ev += f"<br><span style='color:#9ca3af'>ملاحظة: {r['note']}</span>"
            ev += f"<div class='time'>{r['created_at']}</div></div>"
    else:
        ev = "<div class='empty'>لا توجد أدلة بعد</div>"
    html = EVIDENCE_HTML.replace("{eid}", str(eid)).replace("{seller}", e['seller']).replace("{buyer}", e['buyer'] or '—').replace("{count}", str(len(rows))).replace("{evidence_html}", ev)
    return html


@app.route('/escrow/<int:eid>/evidence/add', methods=['POST'])
@login_required
def escrow_evidence_add(eid):
    content = (request.form.get('content') or '').strip()[:50000]
    note = (request.form.get('note') or '').strip()[:300]
    if not content:
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>❌ المحتوى مطلوب</h1><a href='/'>عودة</a>"
    conn = get_db()
    e = conn.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
    if not e or session['user'] not in (e['seller'], e['buyer']):
        conn.close()
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>🚫 غير مخول</h1>"
    conn.execute("INSERT INTO evidence (escrow_id, uploader, content, note) VALUES (?,?,?,?)", (eid, session['user'], content, note))
    conn.commit()
    conn.close()
    return f"<html><head><meta charset='UTF-8'><meta http-equiv='refresh' content='1;url=/escrow/{eid}/evidence'></head><body style='background:#07090e;color:#10b981;text-align:center;font-family:Tahoma;padding:50px'><h1>✅ تم رفع الدليل</h1></body></html>"




CHAT_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>💬 محادثة صفقة #{eid}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Tahoma,sans-serif;background:#07090e;color:#f1f5f9;padding:15px;min-height:100vh}
.c{max-width:700px;margin:auto;background:#111827;padding:20px;border-radius:12px;border:1px solid #1f2937}
h1{color:#38bdf8;text-align:center;font-size:18px;margin-bottom:5px}
.badge{text-align:center;color:#10b981;font-size:12px;margin-bottom:20px}
.chat-box{background:#0b0f19;padding:15px;height:400px;overflow-y:scroll;border:1px solid #4b5563;border-radius:8px;margin-bottom:12px}
.msg{margin-bottom:12px;padding:10px 12px;border-radius:10px;max-width:80%;word-wrap:break-word}
.msg.me{background:#0284c7;color:#fff;margin-left:auto}
.msg.other{background:#374151;color:#f1f5f9}
.msg .time{font-size:10px;color:#cbd5e1;margin-top:5px;opacity:0.7}
.msg .sender{font-size:11px;font-weight:bold;margin-bottom:4px;color:#bfdbfe}
.input-row{display:flex;gap:8px}
input{flex:1;padding:12px;background:#0b0f19;color:#fff;border:1px solid #4b5563;border-radius:8px;font-size:14px}
button{padding:12px 20px;background:#0284c7;color:#fff;border:none;border-radius:8px;font-weight:bold;cursor:pointer;font-size:14px}
button:hover{background:#0369a1}
.back{display:block;text-align:center;color:#38bdf8;text-decoration:none;margin-top:15px;font-size:13px}
</style>
</head>
<body>
<div class="c">
<h1>💬 محادثة الصفقة #{eid}</h1>
<div class="badge">البائع: {seller} | المشتري: {buyer}</div>
<div class="chat-box" id="chatBox">{messages}</div>
<form method="POST" action="/escrow/{eid}/chat/send" class="input-row">
<input type="text" name="body" placeholder="اكتب رسالة..." required maxlength="500" autofocus>
<button type="submit">➤ إرسال</button>
</form>
<a href="/" class="back">← العودة للمنصة</a>
</div>
<script>
var box = document.getElementById('chatBox');
box.scrollTop = box.scrollHeight;
</script>
</body>
</html>
"""


REVIEW_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>⭐ تقييم صفقة #{eid}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Tahoma,sans-serif;background:#07090e;color:#f1f5f9;padding:15px}
.c{max-width:500px;margin:auto;background:#111827;padding:20px;border-radius:12px;border:1px solid #1f2937}
h1{color:#fbbf24;text-align:center;font-size:20px;margin-bottom:5px}
.badge{text-align:center;color:#10b981;font-size:12px;margin-bottom:20px}
.sec{background:#1f2937;padding:15px;border-radius:10px;border:1px solid #374151;margin-bottom:12px}
.sec h3{color:#cbd5e1;margin-bottom:12px;font-size:15px;border-bottom:1px solid #374151;padding-bottom:8px}
label{display:block;color:#94a3b8;font-size:12px;margin:10px 0 6px}
.stars{display:flex;gap:8px;justify-content:center;margin:10px 0}
.star{font-size:36px;cursor:pointer;opacity:0.3;transition:0.2s}
.star.on{opacity:1;transform:scale(1.1)}
textarea{width:100%;padding:11px;background:#0b0f19;color:#fff;border:1px solid #4b5563;border-radius:8px;font-size:14px;font-family:inherit;min-height:80px;resize:vertical}
button{width:100%;padding:13px;background:#fbbf24;color:#000;border:none;border-radius:8px;font-weight:bold;font-size:15px;cursor:pointer;margin-top:12px}
.back{display:block;text-align:center;color:#38bdf8;text-decoration:none;margin-top:15px;font-size:13px}
</style>
</head>
<body>
<div class="c">
<h1>⭐ تقييم الصفقة #{eid}</h1>
<div class="badge">قيّم تجربتك مع {other}</div>
<form method="POST" action="/escrow/{eid}/review/submit" class="sec">
<h3>ما تقييمك؟</h3>
<div class="stars" id="stars">
<span class="star" onclick="setRating(1)">★</span>
<span class="star" onclick="setRating(2)">★</span>
<span class="star" onclick="setRating(3)">★</span>
<span class="star" onclick="setRating(4)">★</span>
<span class="star" onclick="setRating(5)">★</span>
</div>
<input type="hidden" name="rating" id="rating" value="0" required>
<label>تعليق (اختياري)</label>
<textarea name="comment" maxlength="300" placeholder="شارك تجربتك..."></textarea>
<button type="submit">✅ إرسال التقييم</button>
</form>
<a href="/" class="back">← العودة للمنصة</a>
</div>
<script>
function setRating(n){
    document.getElementById('rating').value = n;
    var stars = document.querySelectorAll('.star');
    stars.forEach(function(s, i){ s.classList.toggle('on', i < n); });
}
</script>
</body>
</html>
"""


# ============ CHAT ============
@app.route('/escrow/<int:eid>/chat')
@login_required
def escrow_chat_page(eid):
    conn = get_db()
    e = conn.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
    if not e or session['user'] not in (e['seller'], e['buyer']):
        conn.close()
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>🚫 غير مخول</h1>"
    rows = conn.execute("SELECT * FROM messages WHERE escrow_id=? ORDER BY id ASC LIMIT 200", (eid,)).fetchall()
    conn.close()
    msgs = ""
    for m in rows:
        cls = "me" if m['sender'] == session['user'] else "other"
        msgs += f"<div class='msg {cls}'><div class='sender'>{m['sender']}</div>{m['body']}<div class='time'>{m['created_at']}</div></div>"
    if not msgs:
        msgs = "<p style='text-align:center;color:#6b7280;padding:20px'>لا توجد رسائل - ابدأ المحادثة</p>"
    html = CHAT_HTML.replace("{eid}", str(eid)).replace("{seller}", e['seller']).replace("{buyer}", e['buyer'] or '—').replace("{messages}", msgs)
    return html


@app.route('/escrow/<int:eid>/chat/send', methods=['POST'])
@login_required
def escrow_chat_send(eid):
    body = (request.form.get('body') or '').strip()[:500]
    if not body:
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>❌ رسالة فارغة</h1>"
    conn = get_db()
    e = conn.execute("SELECT * FROM escrows WHERE id=?", (eid,)).fetchone()
    if not e or session['user'] not in (e['seller'], e['buyer']):
        conn.close()
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>🚫 غير مخول</h1>"
    conn.execute("INSERT INTO messages (escrow_id, sender, body) VALUES (?,?,?)", (eid, session['user'], body))
    conn.commit()
    other = e['seller'] if session['user'] == e['buyer'] else e['buyer']
    conn.close()
    try:
        notify(other, "💬 رسالة جديدة", f"من {session['user']} على صفقة #{eid}")
    except: pass
    return f"<html><head><meta charset='UTF-8'><meta http-equiv='refresh' content='0;url=/escrow/{eid}/chat'></head></html>"


# ============ REVIEWS ============
@app.route('/escrow/<int:eid>/review')
@login_required
def escrow_review_page(eid):
    conn = get_db()
    e = conn.execute("SELECT * FROM escrows WHERE id=? AND status='RELEASED'", (eid,)).fetchone()
    if not e or session['user'] not in (e['seller'], e['buyer']):
        conn.close()
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>🚫 غير متاح</h1>"
    if conn.execute("SELECT 1 FROM reviews WHERE escrow_id=? AND reviewer=?", (eid, session['user'])).fetchone():
        conn.close()
        return "<html><head><meta charset='UTF-8'></head><body style='background:#07090e;color:#fbbf24;text-align:center;font-family:Tahoma;padding:50px'><h1>⚠️ قيّمت هذه الصفقة مسبقاً</h1><a href='/' style='color:#38bdf8'>عودة</a></body></html>"
    other = e['seller'] if session['user'] == e['buyer'] else e['buyer']
    conn.close()
    html = REVIEW_HTML.replace("{eid}", str(eid)).replace("{other}", other or 'الطرف الآخر')
    return html


@app.route('/escrow/<int:eid>/review/submit', methods=['POST'])
@login_required
def escrow_review_submit(eid):
    try:
        rating = int(request.form.get('rating', 0))
    except:
        rating = 0
    comment = (request.form.get('comment') or '').strip()[:300]
    if rating < 1 or rating > 5:
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>❌ اختر تقييماً 1-5</h1>"
    conn = get_db()
    e = conn.execute("SELECT * FROM escrows WHERE id=? AND status='RELEASED'", (eid,)).fetchone()
    if not e or session['user'] not in (e['seller'], e['buyer']):
        conn.close()
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>🚫 غير مخول</h1>"
    if conn.execute("SELECT 1 FROM reviews WHERE escrow_id=? AND reviewer=?", (eid, session['user'])).fetchone():
        conn.close()
        return "<h1 style='color:#fbbf24;text-align:center;font-family:Tahoma;padding:50px'>⚠️ قيّمت مسبقاً</h1>"
    reviewee = e['seller'] if session['user'] == e['buyer'] else e['buyer']
    conn.execute("INSERT INTO reviews (escrow_id, reviewer, reviewee, rating, comment) VALUES (?,?,?,?,?)",
                 (eid, session['user'], reviewee, rating, comment))
    conn.commit()
    conn.close()
    try:
        notify(reviewee, "⭐ تقييم جديد", f"حصلت على {rating}/5 من {session['user']}")
    except: pass
    return f"<html><head><meta charset='UTF-8'><meta http-equiv='refresh' content='2;url=/'></head><body style='background:#07090e;color:#10b981;text-align:center;font-family:Tahoma;padding:50px'><h1>✅ شكراً لتقييمك!</h1></body></html>"




PUBLIC_PROFILE_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>👤 {username}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Tahoma,sans-serif;background:#07090e;color:#f1f5f9;padding:15px}
.c{max-width:600px;margin:auto;background:#111827;padding:20px;border-radius:12px;border:1px solid #1f2937}
.avatar{width:80px;height:80px;background:linear-gradient(135deg,#0284c7,#10b981);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:36px;font-weight:bold;color:#fff;margin:0 auto 12px}
h1{color:#38bdf8;text-align:center;font-size:22px;margin-bottom:5px}
.role{text-align:center;color:#9ca3af;font-size:12px;margin-bottom:20px}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:15px}
.stat{background:#1f2937;padding:12px;border-radius:8px;border:1px solid #374151;text-align:center}
.stat .l{color:#9ca3af;font-size:11px;margin-bottom:5px}
.stat .v{font-size:18px;font-weight:bold;color:#10b981}
.stat.gold .v{color:#fbbf24}
.sec{background:#1f2937;padding:15px;border-radius:10px;border:1px solid #374151;margin-bottom:12px}
.sec h3{color:#cbd5e1;margin-bottom:12px;font-size:15px;border-bottom:1px solid #374151;padding-bottom:8px}
.item{background:#0b0f19;padding:12px;margin-top:8px;border-radius:8px;border-right:4px solid #fbbf24;font-size:13px}
.item b{color:#fbbf24}
.stars{color:#fbbf24;font-size:16px;margin:4px 0}
.time{color:#6b7280;font-size:11px;margin-top:5px}
.empty{color:#6b7280;text-align:center;font-size:13px;padding:15px}
.back{display:block;text-align:center;color:#38bdf8;text-decoration:none;margin-top:15px;font-size:13px}
.badge{display:inline-block;background:#10b981;color:#fff;padding:3px 10px;border-radius:20px;font-size:11px;margin:2px}
.badge.gold{background:#fbbf24;color:#000}
</style>
</head>
<body>
<div class="c">
<div class="avatar">{initial}</div>
<h1>{username}</h1>
<div class="role">{role_badges}</div>

<div class="stats">
<div class="stat gold"><div class="l">⭐ Trust Score</div><div class="v">{trust}</div></div>
<div class="stat"><div class="l">📊 صفقات مكتملة</div><div class="v">{deals}</div></div>
<div class="stat"><div class="l">⭐ التقييم</div><div class="v">{avg_rating}</div></div>
<div class="stat"><div class="l">📝 عدد التقييمات</div><div class="v">{review_count}</div></div>
</div>

<div class="sec">
<h3>⭐ التقييمات</h3>
{reviews_html}
</div>

<a href="/" class="back">← العودة للمنصة</a>
</div>
</body>
</html>
"""


@app.route('/u/<username>')
def public_profile(username):
    conn = get_db()
    u = conn.execute("SELECT username, role, kyc_status, trust_score, successful_deals, created_at FROM users WHERE username=?", (username,)).fetchone()
    if not u:
        conn.close()
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>🚫 المستخدم غير موجود</h1>"
    
    reviews = conn.execute("SELECT * FROM reviews WHERE reviewee=? ORDER BY id DESC LIMIT 20", (username,)).fetchall()
    avg = conn.execute("SELECT AVG(rating) as a, COUNT(*) as c FROM reviews WHERE reviewee=?", (username,)).fetchone()
    conn.close()
    
    initial = username[0].upper() if username else "?"
    
    # شارات الدور
    badges = ""
    if u['role'] == 'OWNER':
        badges += "<span class='badge gold'>👑 مالك المنصة</span>"
    if u['kyc_status'] == 'APPROVED':
        badges += "<span class='badge'>✅ موثق KYC</span>"
    if not badges:
        badges = "<span class='badge' style='background:#374151'>👤 مستخدم</span>"
    
    # التقييمات
    if reviews:
        reviews_html = ""
        for r in reviews:
            stars = "⭐" * r['rating']
            reviews_html += f"<div class='item'><b>{r['reviewer']}</b><div class='stars'>{stars}</div>"
            if r['comment']:
                reviews_html += f"<div style='color:#cbd5e1'>{r['comment']}</div>"
            reviews_html += f"<div class='time'>{r['created_at']}</div></div>"
    else:
        reviews_html = "<div class='empty'>لا توجد تقييمات بعد</div>"
    
    avg_val = round(avg['a'], 1) if avg['a'] else 0
    
    html = PUBLIC_PROFILE_HTML.replace("{username}", u['username'])
    html = html.replace("{initial}", initial)
    html = html.replace("{role_badges}", badges)
    html = html.replace("{trust}", str(u['trust_score'] or 100))
    html = html.replace("{deals}", str(u['successful_deals'] or 0))
    html = html.replace("{avg_rating}", f"{avg_val}/5")
    html = html.replace("{review_count}", str(avg['c']))
    html = html.replace("{reviews_html}", reviews_html)
    return html




import urllib.request
import json as _json

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")


def send_telegram(msg):
    try:
        if not TELEGRAM_BOT_TOKEN or TELEGRAM_BOT_TOKEN.startswith("ضع_"):
            return False
        url = "https://api.telegram.org/bot" + TELEGRAM_BOT_TOKEN + "/sendMessage"
        data = _json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"}).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
        return True
    except Exception as e:
        print("[TG]", e)
        return False


@app.route('/api/admin/test-telegram', methods=['POST'])
@login_required
def api_test_telegram():
    if not is_admin():
        return jsonify({"status": "ERROR", "message": "مرفوض"})
    ok = send_telegram("🔔 <b>اختبار ناجح من المنصة</b>")
    return jsonify({"status": "SUCCESS" if ok else "ERROR", "message": "تم" if ok else "فشل"})




DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>📊 لوحة التحليلات</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Tahoma,sans-serif;background:#07090e;color:#f1f5f9;padding:15px}
.c{max-width:1100px;margin:auto;background:#111827;padding:20px;border-radius:12px;border:1px solid #1f2937}
h1{color:#38bdf8;text-align:center;font-size:22px;margin-bottom:5px}
.badge{text-align:center;color:#10b981;font-size:12px;margin-bottom:20px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.stat{background:#1f2937;padding:15px;border-radius:10px;border:1px solid #374151;text-align:center}
.stat .l{color:#9ca3af;font-size:11px;margin-bottom:5px}
.stat .v{font-size:22px;font-weight:bold;color:#10b981}
.stat.gold{border-color:#b45309}.stat.gold .v{color:#fbbf24}
.stat.red{border-color:#7c2d12}.stat.red .v{color:#f87171}
.stat.blue .v{color:#38bdf8}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:15px;margin-bottom:15px}
@media(max-width:768px){.charts{grid-template-columns:1fr}}
.chart-box{background:#1f2937;padding:15px;border-radius:10px;border:1px solid #374151;height:300px;position:relative}
.chart-box h3{color:#cbd5e1;margin-bottom:12px;font-size:14px;border-bottom:1px solid #374151;padding-bottom:8px}
.back{display:block;text-align:center;color:#38bdf8;text-decoration:none;margin-top:15px;font-size:13px;padding:10px;background:#0b0f19;border-radius:8px}
.refresh{background:#0284c7;color:#fff;border:none;padding:8px 15px;border-radius:6px;font-size:13px;cursor:pointer;float:left;margin-bottom:10px}
</style>
</head>
<body>
<div class="c">
<h1>📊 لوحة التحليلات</h1>
<div class="badge">نظرة شاملة على أداء المنصة</div>

<button class="refresh" onclick="location.reload()">🔄 تحديث</button>
<div style="clear:both"></div>

<div class="stats">
<div class="stat blue"><div class="l">👥 المستخدمون</div><div class="v" id="s1">0</div></div>
<div class="stat"><div class="l">📋 إجمالي الصفقات</div><div class="v" id="s2">0</div></div>
<div class="stat gold"><div class="l">💰 رصيد الخزنة</div><div class="v" id="s3">0$</div></div>
<div class="stat gold"><div class="l">📈 العمولات</div><div class="v" id="s4">0$</div></div>
<div class="stat red"><div class="l">⚠️ النزاعات</div><div class="v" id="s5">0</div></div>
<div class="stat"><div class="l">🔒 الصفقات النشطة</div><div class="v" id="s6">0</div></div>
</div>

<div class="charts">
<div class="chart-box"><h3>📊 حالات الصفقات</h3><canvas id="c1"></canvas></div>
<div class="chart-box"><h3>📈 العمولات (آخر 7 أيام)</h3><canvas id="c2"></canvas></div>
</div>

<div class="charts">
<div class="chart-box"><h3>💳 طرق الإيداع</h3><canvas id="c3"></canvas></div>
<div class="chart-box"><h3>👥 حالات KYC</h3><canvas id="c4"></canvas></div>
</div>

<a href="/" class="back">← العودة للمنصة</a>
</div>

<script>
fetch('/api/admin/dashboard-data').then(r=>r.json()).then(d=>{
    if(d.status !== 'SUCCESS'){ alert(d.message); window.location.href = '/'; return; }
    document.getElementById('s1').innerText = d.users;
    document.getElementById('s2').innerText = d.total_escrows;
    document.getElementById('s3').innerText = d.balance.toFixed(2) + '$';
    document.getElementById('s4').innerText = d.commission.toFixed(2) + '$';
    document.getElementById('s5').innerText = d.disputes;
    document.getElementById('s6').innerText = d.locked;
    
    new Chart(document.getElementById('c1'), {
        type: 'doughnut',
        data: {
            labels: ['محررة', 'مقفلة', 'نزاع', 'مستردة', 'ملغاة'],
            datasets: [{ data: [d.released, d.locked, d.disputes, d.refunded, d.cancelled],
                backgroundColor: ['#10b981', '#f59e0b', '#dc2626', '#8b5cf6', '#6b7280'],
                borderColor: '#111827', borderWidth: 2 }]
        },
        options: {
            plugins: { legend: { labels: { color: '#cbd5e1', font: {size: 12} } } },
            maintainAspectRatio: false
        }
    });
    
    new Chart(document.getElementById('c2'), {
        type: 'line',
        data: {
            labels: d.days,
            datasets: [{ label: 'العمولات ($)', data: d.commissions_by_day,
                borderColor: '#fbbf24', backgroundColor: 'rgba(251,191,36,0.2)', tension: 0.3, fill: true, borderWidth: 3 }]
        },
        options: {
            plugins: { legend: { labels: { color: '#cbd5e1' } } },
            scales: { x: { ticks: { color: '#94a3b8' }, grid: { color: '#374151' } },
                     y: { ticks: { color: '#94a3b8' }, beginAtZero: true, grid: { color: '#374151' } } },
            maintainAspectRatio: false
        }
    });
    
    new Chart(document.getElementById('c3'), {
        type: 'bar',
        data: {
            labels: d.deposit_methods.map(x => x.method),
            datasets: [{ label: 'عدد الطلبات', data: d.deposit_methods.map(x => x.count),
                backgroundColor: '#38bdf8', borderRadius: 6 }]
        },
        options: {
            plugins: { legend: { labels: { color: '#cbd5e1' } } },
            scales: { x: { ticks: { color: '#94a3b8' }, grid: { color: '#374151' } },
                     y: { ticks: { color: '#94a3b8' }, beginAtZero: true, grid: { color: '#374151' } } },
            maintainAspectRatio: false
        }
    });
    
    new Chart(document.getElementById('c4'), {
        type: 'pie',
        data: {
            labels: ['موثق', 'قيد المراجعة', 'مرفوض', 'غير مُقدم'],
            datasets: [{ data: [d.kyc_approved, d.kyc_pending, d.kyc_rejected, d.kyc_none],
                backgroundColor: ['#10b981', '#f59e0b', '#dc2626', '#4b5563'],
                borderColor: '#111827', borderWidth: 2 }]
        },
        options: {
            plugins: { legend: { labels: { color: '#cbd5e1' } } },
            maintainAspectRatio: false
        }
    });
}).catch(e=>{ alert('خطأ في التحميل: ' + e); });
</script>
</body>
</html>
"""


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not is_admin():
        return "<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>🚫 مرفوض</h1>"
    return render_template_string(DASHBOARD_HTML)


@app.route('/api/admin/dashboard-data')
@login_required
def api_dashboard_data():
    if not is_admin():
        return jsonify({"status": "ERROR", "message": "مرفوض"})
    conn = get_db()
    users = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()['c']
    total_escrows = conn.execute("SELECT COUNT(*) as c FROM escrows").fetchone()['c']
    disputes = conn.execute("SELECT COUNT(*) as c FROM escrows WHERE status='DISPUTED'").fetchone()['c']
    locked = conn.execute("SELECT COUNT(*) as c FROM escrows WHERE status='LOCKED_SECURE'").fetchone()['c']
    released = conn.execute("SELECT COUNT(*) as c FROM escrows WHERE status='RELEASED'").fetchone()['c']
    refunded = conn.execute("SELECT COUNT(*) as c FROM escrows WHERE status='REFUNDED'").fetchone()['c']
    try:
        cancelled = conn.execute("SELECT COUNT(*) as c FROM escrows WHERE status='CANCELLED'").fetchone()['c']
    except:
        cancelled = 0
    
    t = conn.execute("SELECT * FROM treasury WHERE id=1").fetchone()
    
    # KYC
    kyc_approved = conn.execute("SELECT COUNT(*) as c FROM users WHERE kyc_status='APPROVED'").fetchone()['c']
    kyc_pending = conn.execute("SELECT COUNT(*) as c FROM users WHERE kyc_status='PENDING'").fetchone()['c']
    kyc_rejected = conn.execute("SELECT COUNT(*) as c FROM users WHERE kyc_status='REJECTED'").fetchone()['c']
    kyc_none = conn.execute("SELECT COUNT(*) as c FROM users WHERE kyc_status='NONE' OR kyc_status IS NULL").fetchone()['c']
    
    # عمولات 7 أيام
    rows = conn.execute("""SELECT DATE(timestamp) as d, COALESCE(SUM(amount),0) as s 
        FROM transactions WHERE type IN ('COMMISSION','ESCROW_RELEASE','MILESTONE_RELEASE') 
        AND timestamp >= datetime('now', '-7 days')
        GROUP BY DATE(timestamp) ORDER BY d""").fetchall()
    days_map = {r['d']: r['s'] for r in rows}
    
    from datetime import datetime as _dt, timedelta as _td
    days = []
    vals = []
    for i in range(6, -1, -1):
        day = (_dt.now() - _td(days=i)).strftime('%Y-%m-%d')
        days.append(day[5:])
        vals.append(round(days_map.get(day, 0), 2))
    
    # طرق الإيداع
    try:
        deposit_rows = conn.execute("""SELECT method, COUNT(*) as count FROM pending_deposits 
            GROUP BY method ORDER BY count DESC LIMIT 5""").fetchall()
        deposit_methods = [{'method': r['method'], 'count': r['count']} for r in deposit_rows]
    except:
        deposit_methods = []
    
    if not deposit_methods:
        deposit_methods = [{'method': 'لا توجد', 'count': 0}]
    
    conn.close()
    
    return jsonify({
        "status": "SUCCESS",
        "users": users,
        "total_escrows": total_escrows,
        "disputes": disputes,
        "locked": locked,
        "released": released,
        "refunded": refunded,
        "cancelled": cancelled,
        "balance": t['balance'],
        "commission": t['total_commission'],
        "kyc_approved": kyc_approved,
        "kyc_pending": kyc_pending,
        "kyc_rejected": kyc_rejected,
        "kyc_none": kyc_none,
        "days": days,
        "commissions_by_day": vals,
        "deposit_methods": deposit_methods
    })




from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.units import cm
import io as _io





import arabic_reshaper
from bidi.algorithm import get_display
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

FONT_PATH = os.path.join(os.path.dirname(__file__), 'fonts', 'Amiri-Regular.ttf')
try:
    pdfmetrics.registerFont(TTFont('Amiri', FONT_PATH))
    ARABIC_FONT = 'Amiri'
    print("OK-FONT")
except Exception as _e:
    ARABIC_FONT = 'Helvetica'
    print(f"FONT-ERR: {_e}")


def ar(text):
    try:
        return get_display(arabic_reshaper.reshape(str(text)))
    except:
        return str(text)


@app.route('/api/export/pdf')
@login_required
def api_export_pdf():
    try:
        conn = get_db()
        user = conn.execute("SELECT username, balance, kyc_status, trust_score, referral_code, created_at FROM users WHERE username=?", (session['user'],)).fetchone()
        txs = conn.execute("SELECT * FROM transactions WHERE username=? ORDER BY id DESC LIMIT 50", (session['user'],)).fetchall()
        conn.close()
        
        buf = _io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=1.5*cm, leftMargin=1.5*cm, topMargin=1.5*cm, bottomMargin=1.5*cm)
        story = []
        
        ts = ParagraphStyle('T', fontSize=22, textColor=colors.HexColor('#0284c7'), alignment=1, fontName=ARABIC_FONT, spaceAfter=6)
        ss = ParagraphStyle('S', fontSize=11, textColor=colors.HexColor('#6b7280'), alignment=1, fontName=ARABIC_FONT, spaceAfter=20)
        h2 = ParagraphStyle('H2', fontSize=14, textColor=colors.HexColor('#10b981'), fontName=ARABIC_FONT, spaceAfter=10)
        ft = ParagraphStyle('F', fontSize=8, textColor=colors.grey, alignment=1, fontName=ARABIC_FONT)
        
        story.append(Paragraph(ar("منصة الضمان المالي الآمن"), ts))
        story.append(Paragraph("Enterprise Escrow Platform", ss))
        story.append(Spacer(1, 10))
        story.append(Paragraph(ar("معلومات الحساب"), h2))
        
        info = [
            [ar('البيان'), ar('القيمة')],
            [ar('اسم المستخدم'), str(user['username'])],
            [ar('الرصيد الحالي'), f"{user['balance']:.2f} USD"],
            [ar('حالة KYC'), str(user['kyc_status'])],
            [ar('نقاط الثقة'), str(user['trust_score'] or 100)],
            [ar('كود الإحالة'), str(user['referral_code'] or '-')],
            [ar('تاريخ التسجيل'), str(user['created_at'])],
        ]
        t1 = Table(info, colWidths=[6*cm, 10*cm])
        t1.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0284c7')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f3f4f6')),
            ('TEXTCOLOR', (0,1), (-1,-1), colors.HexColor('#111827')),
            ('ALIGN', (0,0), (-1,-1), 'RIGHT'),
            ('FONT', (0,0), (-1,-1), ARABIC_FONT, 10),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#d1d5db')),
            ('PADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(t1)
        story.append(Spacer(1, 25))
        story.append(Paragraph(ar(f"سجل المعاملات ({len(txs)})"), h2))
        
        data = [[ar('#'), ar('النوع'), ar('المبلغ'), ar('ملاحظة'), ar('التاريخ')]]
        for t in txs:
            data.append([str(t['id']), str(t['type'])[:18], f"{t['amount']}$", ar((t['note'] or '')[:25]), str(t['timestamp'])[:16]])
        if len(data) == 1:
            data.append(['-', ar('لا توجد معاملات'), '-', '-', '-'])
        
        t2 = Table(data, colWidths=[1*cm, 4.5*cm, 2.5*cm, 4.5*cm, 3.5*cm])
        t2.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#10b981')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f9fafb')),
            ('TEXTCOLOR', (0,1), (-1,-1), colors.HexColor('#111827')),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONT', (0,0), (-1,-1), ARABIC_FONT, 8),
            ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#e5e7eb')),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(t2)
        story.append(Spacer(1, 25))
        story.append(Paragraph(ar("تم إنشاء هذا الكشف تلقائياً بواسطة منصة الضمان المالي"), ft))
        story.append(Paragraph(f"(c) EssamElkomy369 - {session['user']}", ft))
        
        doc.build(story)
        buf.seek(0)
        return send_file(buf, mimetype='application/pdf', as_attachment=True, download_name=f'statement_{session["user"]}.pdf')
    except Exception as e:
        return f"<h1 style='color:#f87171;text-align:center;font-family:Tahoma;padding:50px'>خطأ: {e}</h1>"




@app.route('/api/save-email', methods=['POST'])
@login_required
def api_save_email():
    d = request.get_json(silent=True) or {}
    email = (d.get('email') or '').strip()[:100]
    if not email or '@' not in email:
        return jsonify({"status": "ERROR", "message": "بريد غير صالح"})
    conn = get_db()
    conn.execute("UPDATE users SET email=? WHERE username=?", (email, session['user']))
    conn.commit()
    conn.close()
    return jsonify({"status": "SUCCESS", "message": "✅ تم حفظ البريد"})




# ============ EMAIL FUNCTIONS ============
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

GMAIL_USER = os.environ.get("GMAIL_USER", "")
GMAIL_PASS = os.environ.get("GMAIL_PASS", "")





if __name__ == '__main__':
    print("=" * 50)
    print("   Enterprise Escrow - Started")
    print("   Main: http://127.0.0.1:5000")
    print("=" * 50)
    import os as _os
    _port = int(_os.environ.get('PORT', 5000))
    _host = '0.0.0.0' if _os.environ.get('PORT') else '127.0.0.1'
    app.run(host=_host, port=_port, debug=False)
