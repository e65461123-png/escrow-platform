import os, re, threading, time, secrets, sqlite3, pyotp, io, base64
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template_string, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', PERMANENT_SESSION_LIFETIME=timedelta(hours=2))

DATABASE = 'enterprise_escrow.db'
MASTER_OWNER = "EssamElkomy369"
VAULT_PIN = "369246"
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

def notify(u, title, body=''):
    try:
        conn = get_db()
        conn.execute("INSERT INTO notifications (username, title, body) VALUES (?, ?, ?)", (u, title, body))
        conn.close()
    except: pass

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
    if any(w in msg for w in ['نزاع', 'مشكلة']):
        d = c.execute("SELECT COUNT(*) as n FROM escrows WHERE status='DISPUTED'").fetchone()["n"]
        reply = f"🚨 النزاعات: {d}"
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
</div>
<div class="sec"><h3>🔑 تغيير كلمة المرور</h3>
<div class="fg"><label>الحالية</label><input type="password" id="oldP"></div>
<div class="fg"><label>الجديدة</label><input type="password" id="newP"></div>
<button class="bs" onclick="changePwd()">تحديث</button>
</div>
</div>
<div id="v_a" class="hide">
<div class="sec admin" style="display:block">
<h3>⚙️ لوحة المسؤول</h3>
<a href="/vault" style="display:block;text-decoration:none;margin-bottom:10px"><button class="bgold">🔐 الخزنة الخاصة</button></a>
<div class="fg"><input id="banT" placeholder="اسم المستخدم"><button class="bd" onclick="ban()">حظر</button></div>
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
if(id==='n')loadNotifs();if(id==='w')loadWallet();if(id==='p')loadProfile();}
function reg(){let u=document.getElementById('u').value.trim(),p=document.getElementById('p').value;
if(!u||!p)return toast('املأ الحقول','e');
api('/api/register','POST',{username:u,password:p}).then(d=>toast(d.message,d.status==='SUCCESS'?'s':'e'));}
function login(){let u=document.getElementById('u').value.trim(),p=document.getElementById('p').value;
api('/api/login','POST',{username:u,password:p}).then(d=>{
if(d.status!=='SUCCESS')return toast(d.message,'e');
me=u;role=d.role;document.getElementById('who').innerText=u;document.getElementById('bal').innerText=d.balance.toFixed(2)+' $';document.getElementById('trust').innerText=d.trust;
document.getElementById('authView').classList.add('hide');document.getElementById('mainView').classList.remove('hide');
if(d.role==='OWNER')document.getElementById('t_a').classList.remove('hide');
toast('مرحباً '+u,'s');loadEscrows();});}
function logout(){api('/api/logout','POST',{}).then(()=>location.reload());}
function loadEscrows(){fetch('/api/escrows').then(r=>r.json()).then(d=>{
let b=document.getElementById('eList');b.innerHTML='';
if(!d.escrows.length){b.innerHTML="<p style='color:#6b7280;font-size:13px'>لا صفقات.</p>";return;}
d.escrows.forEach(e=>{
let c=e.status==='LOCKED_SECURE'?'locked':e.status==='DISPUTED'?'disputed':'';
let a='';
if(e.status==='LOCKED_SECURE'&&e.buyer===me)a+='<button class="bs" style="padding:6px;font-size:11px;width:auto;margin:3px" onclick="release('+e.id+')">✅ تحرير</button>';
if(e.status==='LOCKED_SECURE'&&(e.buyer===me||e.seller===me))a+='<button class="bw" style="padding:6px;font-size:11px;width:auto;margin:3px" onclick="dispute('+e.id+')">⚠️ نزاع</button>';
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
loadEscrows();
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

@app.route('/')
def index(): return render_template_string(HTML)

@app.route('/owner')
def owner_page(): return render_template_string(OWNER_HTML)

@app.route('/vault')
def vault_page():
    if session.get('user') != MASTER_OWNER:
        return "<h1 style='font-family:Tahoma;color:#f87171;text-align:center;padding:50px'>🚫 مرفوض</h1>", 403
    return render_template_string(VAULT_HTML)

if __name__ == '__main__':
    print("="*50)
    print("   Enterprise Escrow - Started")
    print("   Main: http://127.0.0.1:5000")
    print("   Owner: http://127.0.0.1:5000/owner")
    print("   Vault: http://127.0.0.1:5000/vault")
    print("   Login: EssamElkomy369 / EssamElkomy369")
    print("   PIN: " + VAULT_PIN)
    print("="*50)
    app.run(host='127.0.0.1', port=5000, debug=False)

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
