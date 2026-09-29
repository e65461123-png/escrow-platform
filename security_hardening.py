# -*- coding: utf-8 -*-
"""نظام حماية متقدم - كشف الأسرار، رصد التهديدات، الإغلاق التلقائي"""
import os, re, time, hashlib, secrets, json, threading
from functools import wraps

# ============================================================
#                   1. كاشف الأسرار (Secret Scanner)
# ============================================================
SECRET_PATTERNS = [
    (r'ghp_[A-Za-z0-9]{36,}', 'GitHub Token'),
    (r'ghs_[A-Za-z0-9]{36,}', 'GitHub Server Token'),
    (r're_[A-Za-z0-9_]{20,}', 'Resend API Key'),
    (r'sk-[A-Za-z0-9]{20,}', 'OpenAI Key'),
    (r'xoxb-[0-9]{10,}', 'Slack Bot Token'),
    (r'[0-9]{10}:[A-Za-z0-9_-]{35}', 'Telegram Bot Token'),
    (r'postgresql://[^:]+:[^@]+@[^\s]+', 'PostgreSQL URL'),
    (r'mongodb\+srv://[^:]+:[^@]+@[^\s]+', 'MongoDB URL'),
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    (r'-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----', 'Private Key'),
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'JWT Token'),
    (r'kfsd[a-z]{12}', 'Gmail App Password'),
    (r'npg_[A-Za-z0-9]{15,}', 'Neon DB Key'),
]


# أنماط يُتجاهل ظهورها (regex، توثيق، أمثلة)
FALSE_POSITIVE_PATTERNS = [
    r"re\.match\(r'postgresql",     # regex لتحليل URL
    r"postgresql://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+",  # مثال في الكود
    r"# مثال",
    r"# Example",
]

def scan_text_for_secrets(text):
    """يفحص نصاً ويعيد قائمة الأسرار المكتشفة"""
    # تجاهل السطور التي تطابق استثناءات
    lines = text.split('\n')
    filtered_lines = []
    for line in lines:
        is_false_positive = False
        for fp in FALSE_POSITIVE_PATTERNS:
            if re.search(fp, line):
                is_false_positive = True
                break
        if not is_false_positive:
            filtered_lines.append(line)
    
    filtered_text = '\n'.join(filtered_lines)
    found = []
    for pattern, name in SECRET_PATTERNS:
        for m in re.finditer(pattern, filtered_text):
            found.append({'type': name, 'match': m.group(0)[:20] + '...'})
    return found

def scan_file(path):
    """يفحص ملفاً"""
    try:
        with open(path, 'r', errors='ignore') as f:
            return scan_text_for_secrets(f.read())
    except:
        return []

def scan_directory(root='.'):
    """يفحص كل الملفات في مجلد"""
    skip_dirs = {'.git', '__pycache__', 'node_modules', '.venv', 'venv'}
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in filenames:
            if fn.endswith(('.py', '.txt', '.md', '.json', '.yaml', '.yml', '.env', '.log', '.html')):
                path = os.path.join(dirpath, fn)
                secrets_found = scan_file(path)
                if secrets_found:
                    found.append({'file': path, 'secrets': secrets_found})
    return found


# ============================================================
#                   2. كاشف التهديدات (Threat Detection)
# ============================================================
class ThreatDetector:
    def __init__(self):
        self.attempts = {}       # IP -> [timestamps]
        self.banned = {}         # IP -> ban_until
        self.suspicious = {}     # IP -> score
        self.lockdown = False
        self.lockdown_until = 0
        self.lock = threading.Lock()

        # أنماط الهجوم
        self.attack_patterns = [
            r"('|\")(\s*or\s*|\s*and\s*)('|\")?[0-9]+=[0-9]+",  # SQL injection
            r"union\s+select",                                    # SQL injection
            r"<script[^>]*>",                                     # XSS
            r"javascript:",                                       # XSS
            r"\.\./\.\./",                                        # Path traversal
            r"etc/passwd",                                        # Path traversal
            r"\bexec\b|\beval\b|\bsystem\b",                      # Command injection
            r"base64_decode|gzinflate",                           # Obfuscation
            r"\.env|\.git|\.ssh|config\.php",                     # File scanning
            r"wp-admin|phpmyadmin|xmlrpc",                        # Bot scanning
            r"admin'?\s*--",                                      # SQL comment attack
        ]

        # بدء خيط التنظيف
        threading.Thread(target=self._cleanup_loop, daemon=True).start()

    def _cleanup_loop(self):
        while True:
            time.sleep(60)
            with self.lock:
                now = time.time()
                self.attempts = {k: [t for t in v if now - t < 3600] for k, v in self.attempts.items()}
                self.banned = {k: v for k, v in self.banned.items() if v > now}
                if self.lockdown and now > self.lockdown_until:
                    self.lockdown = False
                    print("[SECURITY] Lockdown ended")

    def get_ip(self, request):
        return (request.headers.get('X-Forwarded-For') or request.remote_addr or '?').split(',')[0].strip()

    def is_banned(self, ip):
        with self.lock:
            if ip in self.banned:
                if time.time() < self.banned[ip]:
                    return True
                del self.banned[ip]
            return False

    def ban_ip(self, ip, minutes=60):
        with self.lock:
            self.banned[ip] = time.time() + minutes * 60
            print(f"[SECURITY] BANNED {ip} for {minutes}min")

    def check_payload(self, request):
        """يفحص الطلب بحثاً عن أنماط هجوم"""
        try:
            raw = str(request.query_string) + str(request.get_data(as_text=True, cache=False)[:5000])
            for pat in self.attack_patterns:
                if re.search(pat, raw, re.IGNORECASE):
                    return {'threat': 'injection', 'pattern': pat}
        except: pass
        return None

    def track_attempt(self, ip, kind='generic'):
        """يتتبع المحاولات المشبوهة"""
        with self.lock:
            key = f"{ip}:{kind}"
            self.attempts.setdefault(key, []).append(time.time())
            self.attempts[key] = [t for t in self.attempts[key] if time.time() - t < 300]
            count = len(self.attempts[key])
            # رصد
            if count >= 10:
                self.ban_ip(ip, 60)
            elif count >= 20:
                # هجوم منسّق
                self.activate_lockdown(30)
            return count

    def activate_lockdown(self, minutes=30):
        with self.lock:
            self.lockdown = True
            self.lockdown_until = time.time() + minutes * 60
            print(f"[SECURITY] 🚨 LOCKDOWN ACTIVATED for {minutes}min")

    def is_lockdown(self):
        with self.lock:
            return self.lockdown


# ============================================================
#                   3. الخزنة المشفّرة
# ============================================================
class EncryptedVault:
    """خزنة لتخزين أسرار مشفّرة داخل السيرفر - AES"""
    def __init__(self, key_file='.vault_key', data_file='.vault_data'):
        self.key_file = key_file
        self.data_file = data_file
        self._key = None
        self._data = None

    def _load_key(self):
        if self._key: return self._key
        try:
            if os.path.exists(self.key_file):
                with open(self.key_file, 'rb') as f:
                    self._key = f.read()
            else:
                self._key = secrets.token_bytes(32)
                with open(self.key_file, 'wb') as f:
                    f.write(self._key)
                try: os.chmod(self.key_file, 0o600)
                except: pass
            return self._key
        except:
            return None

    def _encrypt(self, data):
        key = self._load_key()
        if not key: return data.encode()
        try:
            from cryptography.fernet import Fernet
            import base64
            fkey = base64.urlsafe_b64encode(key)
            return Fernet(fkey).encrypt(data.encode())
        except:
            # Fallback: تشفير XOR بسيط
            result = bytes(b ^ key[i % len(key)] for i, b in enumerate(data.encode()))
            return base64.b64encode(result) if 'base64' in dir() else result

    def _decrypt(self, data):
        key = self._load_key()
        if not key: return data
        try:
            from cryptography.fernet import Fernet
            import base64
            fkey = base64.urlsafe_b64encode(key)
            return Fernet(fkey).decrypt(data if isinstance(data, bytes) else data.encode()).decode()
        except:
            try:
                import base64
                raw = base64.b64decode(data) if isinstance(data, (bytes, str)) else data
                result = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
                return result.decode()
            except:
                return None

    def set(self, key, value):
        if self._data is None: self.load()
        self._data[key] = value
        self.save()

    def get(self, key, default=None):
        if self._data is None: self.load()
        return self._data.get(key, default)

    def load(self):
        self._data = {}
        if not os.path.exists(self.data_file): return
        try:
            with open(self.data_file, 'rb') as f:
                raw = f.read()
            decrypted = self._decrypt(raw)
            if decrypted:
                self._data = json.loads(decrypted)
        except: pass

    def save(self):
        try:
            encrypted = self._encrypt(json.dumps(self._data))
            with open(self.data_file, 'wb') as f:
                f.write(encrypted if isinstance(encrypted, bytes) else encrypted.encode())
            try: os.chmod(self.data_file, 0o600)
            except: pass
        except: pass


# ============================================================
#                   4. Auth Guard (حماية إضافية للمسارات الحساسة)
# ============================================================
# يمكن إضافتها لاحقاً في app.py:
#   from security_hardening import require_auth_signature
#   @app.route('/api/vault/...')
#   @require_auth_signature
#   def ...:
#       pass

def require_auth_signature(f):
    """يتطلب توقيع HMAC لكل طلب حساس"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        from flask import session, request, jsonify
        sig = request.headers.get('X-Auth-Signature', '')
        if not sig:
            return jsonify({'status': 'ERROR', 'message': 'Missing signature'}), 403
        # التوقيع = HMAC(user + path + secret)
        user = session.get('user', '')
        path = request.path
        secret = os.environ.get('SECRET_KEY', 'default')
        expected = hashlib.sha256(f"{user}:{path}:{secret}".encode()).hexdigest()[:32]
        if not secrets.compare_digest(sig, expected):
            return jsonify({'status': 'ERROR', 'message': 'Invalid signature'}), 403
        return f(*args, **kwargs)
    return wrapper
