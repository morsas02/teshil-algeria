import smtplib, ssl
import time
import secrets
from email.message import EmailMessage
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_from_directory, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3, os, re, json, uuid, glob, threading, traceback

try:
    from pywebpush import webpush
    HAVE_PYWEBPUSH = True
except Exception:
    webpush = None
    HAVE_PYWEBPUSH = False

VAPID_PUBLIC_KEY = os.environ.get('VAPID_PUBLIC_KEY', '')
VAPID_PRIVATE_KEY = os.environ.get('VAPID_PRIVATE_KEY', '').replace('\\n', '\n')
VAPID_SUBJECT = os.environ.get('VAPID_SUBJECT', 'mailto:admin@ta9eef.dz')

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_SECURE=os.environ.get('BASE_URL', '').startswith('https'),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_PERMANENT=True,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32).hex()
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

STORAGE_ROOT = os.environ.get('STORAGE_ROOT', os.path.join(app.root_path, 'static'))

@app.route('/static/uploads/<path:filename>')
def serve_uploads(filename):
    base = os.path.join(STORAGE_ROOT, 'uploads')
    local = os.path.join(app.root_path, 'static', 'uploads')
    source = base if os.path.exists(os.path.join(base, filename)) else local
    return send_from_directory(source, filename)

@app.route('/static/receipts/<path:filename>')
def serve_receipt_files(filename):
    base = os.path.join(STORAGE_ROOT, 'receipts')
    local = os.path.join(app.root_path, 'static', 'receipts')
    source = base if os.path.exists(os.path.join(base, filename)) else local
    return send_from_directory(source, filename)

@app.template_filter('date')
def date_filter(val):
    if val is None:
        return ''
    if isinstance(val, str):
        return val[:10]
    return val.strftime('%Y-%m-%d')

limiter = Limiter(app=app, key_func=get_remote_address, storage_uri='memory://')

CSRF_SAFE_ENDPOINTS = {'login', 'register', 'forgot_password', 'reset_password',
                       'google_callback', 'facebook_callback', 'serve_static', 'serve_root_files', 'contact'}

@app.before_request
def csrf_protect():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    if request.method == 'POST' and request.endpoint not in CSRF_SAFE_ENDPOINTS:
        token = request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': 'CSRF token invalid'}), 400
            flash('انتهت صلاحية الجلسة، حاول مرة أخرى', 'danger')
            return redirect(request.referrer or url_for('index'))

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://apis.google.com 'unsafe-inline'; style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'"
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

DB_PATH = os.path.join(os.path.dirname(__file__), 'ta9eef.db')

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    tb = traceback.format_exc()
    print(tb)
    return render_template('500.html'), 500

ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@ta9eef.dz')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123456')
JOB_PRICE = 1000
AD_PRICE_PER_WEEK = 5000
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
AVATAR_MAX_SIZE = 2 * 1024 * 1024
ALLOWED_RECEIPT_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'pdf'}
RECEIPT_MAX_SIZE = 5 * 1024 * 1024

def validate_image(fp):
    header = fp.read(32)
    fp.seek(0)
    if header[:8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    if header[:2] in (b'\xff\xd8',):
        return 'jpeg'
    if header[:6] in (b'GIF87a', b'GIF89a'):
        return 'gif'
    if header[:4] == b'RIFF' and header[8:12] == b'WEBP':
        return 'webp'
    return None

def get_avatar_url(row):
    try:
        return row['avatar_url'] or ''
    except (KeyError, IndexError):
        return ''

# OAuth configuration (set from admin settings or env)
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
FACEBOOK_APP_ID = os.environ.get('FACEBOOK_APP_ID', '')
FACEBOOK_APP_SECRET = os.environ.get('FACEBOOK_APP_SECRET', '')
BASE_URL = os.environ.get('BASE_URL', 'http://localhost:8080')
SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')

BREVO_API_KEY = os.environ.get('BREVO_API_KEY', '')
BREVO_SENDER = os.environ.get('BREVO_SENDER', '')
BREVO_SENDER_NAME = os.environ.get('BREVO_SENDER_NAME', 'تسهيل')

def _send_via_brevo(to, subject, text, html=None):
    def _run():
        try:
            import requests
            payload = {
                'sender': {'name': BREVO_SENDER_NAME, 'email': BREVO_SENDER},
                'to': [{'email': to}],
                'subject': subject,
                'textContent': text,
            }
            if html:
                payload['htmlContent'] = html
            resp = requests.post('https://api.brevo.com/v3/smtp/email',
                                 json=payload, headers={'api-key': BREVO_API_KEY},
                                 timeout=15)
            print(f'Brevo send: {resp.status_code} {resp.text[:200]}', flush=True)
        except Exception as e:
            print(f'Brevo error: {e}', flush=True)
    threading.Thread(target=_run, daemon=True).start()

def send_email(to, subject, text, html=None):
    if BREVO_API_KEY and BREVO_SENDER:
        return _send_via_brevo(to, subject, text, html)
    if not (SMTP_USER and SMTP_PASSWORD):
        return
    def _run():
        try:
            msg = EmailMessage()
            msg['Subject'] = subject
            msg['From'] = SMTP_USER
            msg['To'] = to
            msg.set_content(text)
            if html:
                msg.add_alternative(html, subtype='html')
            context = ssl.create_default_context()
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
                server.starttls(context=context)
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
            print(f'Email sent to {to}')
        except Exception as e:
            print(f'SMTP error: {e}')
    threading.Thread(target=_run, daemon=True).start()

ALGERIAN_WILAYAS = [
    "أدرار", "الشلف", "الأغواط", "أم البواقي", "باتنة", "بجاية", "بسكرة", "بشار",
    "البليدة", "البويرة", "تمنراست", "تبسة", "تلمسان", "تيارت", "تيزي وزو", "الجزائر",
    "الجلفة", "جيجل", "سطيف", "سعيدة", "سكيكدة", "سيدي بلعباس", "عنابة", "قالمة",
    "قسنطينة", "المدية", "مستغانم", "المسيلة", "معسكر", "وهران", "ورقلة", "إليزي",
    "برج بوعريريج", "بومرداس", "الطارف", "تندوف", "تسمسيلت", "الوادي", "خنشلة",
    "سوق أهراس", "تيبازة", "ميلة", "عين الدفلى", "النعامة", "عين تموشنت", "غرداية",
    "غليزان", "تميمون", "برج باجي مختار", "أولاد جلال", "بني عباس", "عين صالح",
    "عين قزام", "توقرت", "جانت", "المنيعة", "المغير"
]

WILAYA_SLUGS = {
    'adrar': 'أدرار', 'chlef': 'الشلف', 'laghouat': 'الأغواط', 'oum-el-bouaghi': 'أم البواقي',
    'batna': 'باتنة', 'bejaia': 'بجاية', 'biskra': 'بسكرة', 'bechar': 'بشار',
    'blida': 'البليدة', 'bouira': 'البويرة', 'tamanrasset': 'تمنراست', 'tebessa': 'تبسة',
    'tlemcen': 'تلمسان', 'tiaret': 'تيارت', 'tizi-ouzou': 'تيزي وزو', 'alger': 'الجزائر',
    'djelfa': 'الجلفة', 'jijel': 'جيجل', 'setif': 'سطيف', 'saida': 'سعيدة',
    'skikda': 'سكيكدة', 'sidi-bel-abbes': 'سيدي بلعباس', 'annaba': 'عنابة', 'guelma': 'قالمة',
    'constantine': 'قسنطينة', 'medea': 'المدية', 'mostaganem': 'مستغانم', 'msila': 'المسيلة',
    'mascara': 'معسكر', 'oran': 'وهران', 'ouargla': 'ورقلة', 'illizi': 'إليزي',
    'bordj-bou-arreridj': 'برج بوعريريج', 'boumerdes': 'بومرداس', 'el-tarf': 'الطارف', 'tindouf': 'تندوف',
    'tissemsilt': 'تسمسيلت', 'el-oued': 'الوادي', 'khenchela': 'خنشلة',
    'souk-ahras': 'سوق أهراس', 'tipaza': 'تيبازة', 'mila': 'ميلة', 'ain-defla': 'عين الدفلى',
    'naama': 'النعامة', 'ain-temouchent': 'عين تموشنت', 'ghardaia': 'غرداية', 'relizane': 'غليزان',
    'timimoun': 'تميمون', 'bordj-badji-mokhtar': 'برج باجي مختار', 'ouled-djellal': 'أولاد جلال',
    'beni-abbes': 'بني عباس', 'in-salah': 'عين صالح', 'in-guezzam': 'عين قزام',
    'touggourt': 'توقرت', 'djanet': 'جانت', 'el-meniaa': 'المنيعة', 'el-mghair': 'المغير',
}

JOB_CATEGORIES = [
    "تكنولوجيا المعلومات", "الهندسة", "المحاسبة والمالية", "التسويق والمبيعات",
    "الموارد البشرية", "الإدارة", "الصناعة", "البناء والأشغال", "السياحة والفندقة",
    "الصحة", "التعليم", "الزراعة", "النقل واللوجستيك", "الإعلام الآلي",
    "الاتصالات", "الخدمات", "القانون", "الإعلام والصحافة", "الطاقة", "الصيدلة"
]

CONTRACT_TYPES = ["دوام كامل", "دوام جزئي", "مؤقت", "عن بعد", "موسمي", "تدريب"]

EXPERIENCE_LEVELS = ["مبتدئ (أقل من سنة)", "Junior (1-3 سنوات)", "Mid (3-5 سنوات)", "Senior (5-10 سنوات)", "خبير (أكثر من 10 سنوات)"]

class DB:
    _pool = None

    def __init__(self):
        self._closed = False
        self._url = os.environ.get('DATABASE_URL', '')
        if self._url:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            from psycopg2.pool import ThreadedConnectionPool
            if DB._pool is None:
                DB._pool = ThreadedConnectionPool(1, 4, self._url, cursor_factory=RealDictCursor)
            try:
                self._conn = DB._pool.getconn()
            except Exception:
                DB._pool = ThreadedConnectionPool(1, 4, self._url, cursor_factory=RealDictCursor)
                self._conn = DB._pool.getconn()
        else:
            self._conn = sqlite3.connect(DB_PATH, timeout=15)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=10000")
            self._conn.execute("PRAGMA foreign_keys=ON")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        self.close()

    def execute(self, sql, params=None):
        sql = sql.replace('%s', '?') if not self._url else sql
        try:
            if self._url:
                cur = self._conn.cursor()
                cur.execute(sql, params if params else None)
                return cur
            return self._conn.execute(sql, params or ())
        except Exception as e:
            print(f'DB ERROR: {sql[:200]} | {e}')
            raise

    def executemany(self, sql, params_list):
        sql = sql.replace('%s', '?') if not self._url else sql
        if self._url:
            cur = self._conn.cursor()
            for p in params_list:
                cur.execute(sql, p)
            return
        self._conn.executemany(sql, params_list)

    def executescript(self, sql):
        if self._url:
            for stmt in sql.split(';'):
                s = stmt.strip()
                if s:
                    self._conn.execute(s + ';')
        else:
            self._conn.executescript(sql)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        try:
            self._conn.rollback()
        except Exception:
            pass

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._url and DB._pool:
            DB._pool.putconn(self._conn)
        else:
            self._conn.close()


def get_db():
    return DB()

def _ddl(sql, is_pg):
    if is_pg:
        return sql.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'SERIAL PRIMARY KEY')
    return sql

SCHEMA = '''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        password TEXT NOT NULL,
        user_type TEXT NOT NULL CHECK(user_type IN ('worker','employer','admin')),
        is_verified INTEGER DEFAULT 0,
        avatar_url TEXT,
        wallet_balance REAL DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS workers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        skills TEXT,
        experience_years INTEGER DEFAULT 0,
        experience_level TEXT,
        education TEXT,
        city TEXT,
        wilaya TEXT,
        about TEXT,
        cv_url TEXT,
        linkedin_url TEXT,
        portfolio_url TEXT,
        availability TEXT DEFAULT 'متاح',
        expected_salary INTEGER,
        birth_year INTEGER,
        gender TEXT,
        is_public INTEGER DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS employers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        company_name TEXT NOT NULL,
        company_description TEXT,
        company_website TEXT,
        company_logo TEXT,
        company_size TEXT,
        company_sector TEXT,
        city TEXT,
        wilaya TEXT,
        address TEXT,
        phone TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        employer_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        requirements TEXT,
        responsibilities TEXT,
        benefits TEXT,
        contract_type TEXT,
        experience_level TEXT,
        city TEXT,
        wilaya TEXT,
        category TEXT,
        salary_min INTEGER,
        salary_max INTEGER,
        currency TEXT DEFAULT 'دج',
        positions_count INTEGER DEFAULT 1,
        is_urgent INTEGER DEFAULT 0,
        is_featured INTEGER DEFAULT 0,
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','closed')),
        views_count INTEGER DEFAULT 0,
        applications_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (employer_id) REFERENCES employers(id)
    );

    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id INTEGER NOT NULL,
        worker_id INTEGER NOT NULL,
        message TEXT,
        cover_letter TEXT,
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending','reviewed','accepted','rejected')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (job_id) REFERENCES jobs(id),
        FOREIGN KEY (worker_id) REFERENCES workers(id)
    );

    CREATE TABLE IF NOT EXISTS saved_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        worker_id INTEGER NOT NULL,
        job_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (worker_id) REFERENCES workers(id),
        FOREIGN KEY (job_id) REFERENCES jobs(id)
    );

    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        worker_id INTEGER NOT NULL,
        type TEXT NOT NULL CHECK(type IN ('request','appointment','info')),
        employer_id INTEGER,
        job_id INTEGER,
        subject TEXT,
        message TEXT,
        preferred_date TEXT,
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending','accepted','rejected','completed','answered')),
        admin_reply TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (worker_id) REFERENCES workers(id),
        FOREIGN KEY (employer_id) REFERENCES employers(id),
        FOREIGN KEY (job_id) REFERENCES jobs(id)
    );

    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        message TEXT,
        type TEXT DEFAULT 'info',
        is_read INTEGER DEFAULT 0,
        link TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS push_subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        endpoint TEXT NOT NULL,
        p256dh TEXT NOT NULL,
        auth TEXT NOT NULL,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        employer_id INTEGER NOT NULL,
        worker_id INTEGER NOT NULL,
        rating INTEGER CHECK(rating >= 1 AND rating <= 5),
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (employer_id) REFERENCES employers(id),
        FOREIGN KEY (worker_id) REFERENCES workers(id)
    );

    CREATE TABLE IF NOT EXISTS contact_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        subject TEXT,
        message TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
    CREATE INDEX IF NOT EXISTS idx_jobs_wilaya ON jobs(wilaya);
    CREATE INDEX IF NOT EXISTS idx_jobs_category ON jobs(category);
    CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at);
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);

    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL CHECK(type IN ('credit','debit')),
        amount REAL NOT NULL,
        balance_before REAL DEFAULT 0,
        balance_after REAL DEFAULT 0,
        description TEXT,
        reference_type TEXT,
        reference_id INTEGER,
        status TEXT DEFAULT 'completed' CHECK(status IN ('pending','completed','cancelled')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS packages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        credits INTEGER NOT NULL,
        price REAL NOT NULL,
        duration_days INTEGER DEFAULT 365,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS payment_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        package_id INTEGER,
        amount REAL NOT NULL,
        credits INTEGER DEFAULT 0,
        reference TEXT UNIQUE NOT NULL,
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending','confirmed','cancelled','expired')),
        receipt_path TEXT,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (package_id) REFERENCES packages(id)
    );

    CREATE TABLE IF NOT EXISTS banners (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        image_url TEXT NOT NULL,
        link_url TEXT DEFAULT '',
        position TEXT DEFAULT 'home_top' CHECK(position IN ('home_top','home_bottom')),
        is_active INTEGER DEFAULT 1,
        sort_order INTEGER DEFAULT 0,
        clicks INTEGER DEFAULT 0,
        ends_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS banner_clicks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        banner_id INTEGER NOT NULL,
        referrer TEXT DEFAULT '',
        clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (banner_id) REFERENCES banners(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS ad_orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        image_url TEXT NOT NULL,
        link_url TEXT DEFAULT '',
        position TEXT DEFAULT 'home_top' CHECK(position IN ('home_top','home_bottom')),
        duration_days INTEGER NOT NULL DEFAULT 7,
        price REAL NOT NULL DEFAULT 0,
        status TEXT DEFAULT 'pending_payment' CHECK(status IN ('pending_payment','paid','active','expired','cancelled','rejected')),
        receipt_path TEXT,
        starts_at TIMESTAMP,
        ends_at TIMESTAMP,
        banner_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
'''

def _table_names(conn):
    if os.environ.get('DATABASE_URL'):
        rows = conn.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'").fetchall()
        return [r['table_name'] for r in rows]
    return [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()]

def _json_default(o):
    if isinstance(o, (datetime,)):
        return o.isoformat()
    if isinstance(o, (bytes, bytearray)):
        return o.decode('utf-8', 'replace')
    return str(o)

def write_data_backup():
    backup_dir = os.path.join(STORAGE_ROOT, 'backups')
    os.makedirs(backup_dir, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    path = os.path.join(backup_dir, f'ta9eef-data-{stamp}.json')
    conn = get_db()
    data = {}
    for table in _table_names(conn):
        rows = conn.execute('SELECT * FROM ' + table).fetchall()
        data[table] = [dict(r) for r in rows]
    conn.close()
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, default=_json_default)
    keep = sorted(glob.glob(os.path.join(backup_dir, 'ta9eef-data-*.json')))[:-7]
    for old in keep:
        try:
            os.remove(old)
        except OSError:
            pass
    return path

def _expire_overdue_orders():
    conn = get_db()
    conn.execute("UPDATE ad_orders SET status = 'expired', updated_at = CURRENT_TIMESTAMP WHERE status = 'active' AND ends_at IS NOT NULL AND ends_at <= CURRENT_TIMESTAMP")
    conn.commit()
    conn.close()

def refresh_ad_order_statuses():
    try:
        _expire_overdue_orders()
    except Exception:
        traceback.print_exc()

def _maintenance():
    refresh_ad_order_statuses()
    try:
        write_data_backup()
    except Exception:
        traceback.print_exc()

def _daily_loop():
    _maintenance()
    while True:
        time.sleep(24 * 3600)
        _maintenance()

def init_db():
    conn = get_db()
    is_pg = bool(os.environ.get('DATABASE_URL', ''))
    if is_pg:
        for stmt in SCHEMA.split(';'):
            s = stmt.strip()
            if s:
                conn.execute(_ddl(s, True) + ';')
        conn.commit()
    else:
        conn.executescript(_ddl(SCHEMA, False))

    if is_pg:
        has_col = conn.execute("SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'is_active'").fetchone()
        if not has_col:
            conn.execute('ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1')
            conn.commit()
    else:
        try:
            conn.execute('ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1')
            conn.commit()
        except Exception:
            conn.rollback()

    if is_pg:
        has_unique = conn.execute("SELECT 1 FROM pg_constraint WHERE conrelid = 'packages'::regclass AND contype = 'u' AND pg_get_constraintdef(oid) LIKE '%UNIQUE (name)%'").fetchone()
        if not has_unique:
            try:
                conn.execute("ALTER TABLE packages ADD UNIQUE (name)")
                conn.commit()
            except Exception:
                conn.rollback()

    admin = conn.execute('SELECT id, password FROM users WHERE user_type = %s ORDER BY id LIMIT 1', ('admin',)).fetchone()
    if not admin:
        admin = conn.execute('SELECT id, password FROM users WHERE email = %s', (ADMIN_EMAIL,)).fetchone()
    if not admin:
        hashed = generate_password_hash(ADMIN_PASSWORD)
        conn.execute(
            "INSERT INTO users (full_name, email, password, user_type, is_verified, wallet_balance) VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT(email) DO NOTHING" if is_pg else
            'INSERT OR IGNORE INTO users (full_name, email, password, user_type, is_verified, wallet_balance) VALUES (%s, %s, %s, %s, %s, %s)',
            ('مدير المنصة', ADMIN_EMAIL, hashed, 'admin', 1, 999999)
        )
    elif ADMIN_PASSWORD != 'admin123456' and check_password_hash(admin['password'], 'admin123456'):
        conn.execute('UPDATE users SET password = %s WHERE id = %s', (generate_password_hash(ADMIN_PASSWORD), admin['id']))

    if not conn.execute('SELECT key FROM settings WHERE key = %s', ('job_price',)).fetchone():
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (%s, %s) ON CONFLICT(key) DO NOTHING" if is_pg else
            'INSERT OR IGNORE INTO settings (key, value) VALUES (%s, %s)',
            ('job_price', str(JOB_PRICE))
        )

    if not conn.execute('SELECT key FROM settings WHERE key = %s', ('ad_price_per_week',)).fetchone():
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (%s, %s) ON CONFLICT(key) DO NOTHING" if is_pg else
            'INSERT OR IGNORE INTO settings (key, value) VALUES (%s, %s)',
            ('ad_price_per_week', str(AD_PRICE_PER_WEEK))
        )

    payment_defaults = {'payment_phone': '+213670729307', 'payment_ccp_name': 'mosrsizitouni', 'payment_ccp_rib': '0028284754cle89', 'payment_baridi': ''}
    for k, v in payment_defaults.items():
        if is_pg:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (%s, %s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
                (k, v)
            )
        else:
            conn.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (%s, %s)', (k, v))

    default_packages = [
        ('باقة التجربة', 3, 2000, 30),
        ('باقة النمو', 10, 5000, 90),
        ('باقة الاحترافية', 30, 12000, 365),
        ('باقة غير محدود', 100, 30000, 365),
    ]
    existing_count = conn.execute('SELECT COUNT(*) as c FROM packages').fetchone()['c']
    if existing_count == 0:
        for name, credits, price, days in default_packages:
            conn.execute(
                "INSERT INTO packages (name, credits, price, duration_days) VALUES (%s, %s, %s, %s) ON CONFLICT(name) DO NOTHING" if is_pg else
                'INSERT OR IGNORE INTO packages (name, credits, price, duration_days) VALUES (%s, %s, %s, %s)',
                (name, credits, price, days)
            )

    conn.commit()
    conn.close()

init_db()

threading.Thread(target=_daily_loop, daemon=True).start()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('الرجاء تسجيل الدخول أولاً', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if session.get('user_type') != 'admin':
            flash('هذه الصفحة مخصصة للمشرفين فقط', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

def worker_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if session.get('user_type') != 'worker':
            conn = get_db()
            worker = conn.execute('SELECT id FROM workers WHERE user_id = %s', (session['user_id'],)).fetchone()
            conn.close()
            if worker:
                session['user_type'] = 'worker'
                return f(*args, **kwargs)
            flash('هذه الصفحة مخصصة للباحثين عن عمل فقط', 'warning')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

def employer_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if session.get('user_type') != 'employer':
            conn = get_db()
            employer = conn.execute('SELECT id FROM employers WHERE user_id = %s', (session['user_id'],)).fetchone()
            conn.close()
            if employer:
                session['user_type'] = 'employer'
                return f(*args, **kwargs)
            flash('هذه الصفحة مخصصة لأرباب العمل فقط', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

def notify(user_id, title, message, type='info', link=None, conn=None):
    if conn:
        conn.execute(
            'INSERT INTO notifications (user_id, title, message, type, link) VALUES (%s, %s, %s, %s, %s)',
            (user_id, title, message, type, link)
        )
        return
    for attempt in range(5):
        try:
            c = get_db()
            c.execute(
                'INSERT INTO notifications (user_id, title, message, type, link) VALUES (%s, %s, %s, %s, %s)',
                (user_id, title, message, type, link)
            )
            c.commit()
            c.close()
            return
        except Exception:
            time.sleep(0.1 * (attempt + 1))

def get_unread_count(user_id):
    conn = get_db()
    count = conn.execute('SELECT COUNT(*) as c FROM notifications WHERE user_id = %s AND is_read = 0', (user_id,)).fetchone()
    conn.close()
    return count['c']

def notify_admin(title, message, link=None):
    try:
        conn = get_db()
        admin = conn.execute("SELECT id FROM users WHERE user_type = 'admin' ORDER BY id LIMIT 1").fetchone()
        if admin:
            conn.execute(
                'INSERT INTO notifications (user_id, title, message, type, link) VALUES (%s, %s, %s, %s, %s)',
                (admin['id'], title, message, 'admin', link)
            )
            conn.commit()
        conn.close()
    except Exception:
        pass

def send_push(subscription, title, body, url=None):
    if not (HAVE_PYWEBPUSH and VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY):
        return False
    try:
        webpush(
            subscription_info={
                'endpoint': subscription['endpoint'],
                'keys': {'p256dh': subscription['p256dh'], 'auth': subscription['auth']},
            },
            data=json.dumps({'title': title, 'body': body, 'url': url or '/'}),
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims={'sub': VAPID_SUBJECT},
        )
        return True
    except Exception:
        return False

def notify_all_subscribers(title, body, url=None):
    try:
        conn = get_db()
        subs = conn.execute('SELECT DISTINCT endpoint, p256dh, auth FROM push_subscriptions').fetchall()
        conn.close()
    except Exception:
        return
    dead = []
    for s in subs:
        if not send_push(s, title, body, url):
            dead.append(s['endpoint'])
    if dead:
        try:
            conn = get_db()
            for ep in dead:
                conn.execute('DELETE FROM push_subscriptions WHERE endpoint = %s', (ep,))
            conn.commit()
            conn.close()
        except Exception:
            pass

@app.route('/push/subscribe', methods=['POST'])
@login_required
def push_subscribe():
    try:
        data = request.get_json(silent=True) or {}
        endpoint = data.get('endpoint')
        keys = data.get('keys') or {}
        p256dh = keys.get('p256dh')
        auth = keys.get('auth')
        if not (endpoint and p256dh and auth):
            return jsonify({'ok': False, 'error': 'بيانات غير مكتملة'}), 400
        conn = get_db()
        conn.execute('DELETE FROM push_subscriptions WHERE endpoint = %s', (endpoint,))
        conn.execute(
            'INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth, user_agent) VALUES (%s, %s, %s, %s, %s)',
            (session['user_id'], endpoint, p256dh, auth, (request.headers.get('User-Agent', '') or '')[:200])
        )
        conn.commit()
        conn.close()
        return jsonify({'ok': True})
    except Exception:
        return jsonify({'ok': False, 'error': 'خطأ في الحفظ'}), 500

@app.route('/push/unsubscribe', methods=['POST'])
def push_unsubscribe():
    data = request.get_json(silent=True) or {}
    endpoint = data.get('endpoint')
    if not endpoint:
        return jsonify({'ok': False}), 400
    try:
        conn = get_db()
        conn.execute('DELETE FROM push_subscriptions WHERE endpoint = %s', (endpoint,))
        conn.commit()
        conn.close()
        return jsonify({'ok': True})
    except Exception:
        return jsonify({'ok': False}), 500

@app.route('/push/vapid-key')
def push_vapid_key():
    return jsonify({'key': VAPID_PUBLIC_KEY})

_stats_cache = {'t': 0.0, 'data': None}

def get_stats():
    import time
    now = time.time()
    if _stats_cache['data'] is not None and now - _stats_cache['t'] < 60:
        return _stats_cache['data']
    conn = get_db()
    stats = {
        'total_jobs': conn.execute('SELECT COUNT(*) as c FROM jobs').fetchone()['c'],
        'active_jobs': conn.execute("SELECT COUNT(*) as c FROM jobs WHERE status = 'approved'").fetchone()['c'],
        'total_workers': conn.execute("SELECT COUNT(*) as c FROM users WHERE user_type = 'worker'").fetchone()['c'],
        'total_employers': conn.execute("SELECT COUNT(*) as c FROM users WHERE user_type = 'employer'").fetchone()['c'],
        'pending_jobs': conn.execute("SELECT COUNT(*) as c FROM jobs WHERE status = 'pending'").fetchone()['c'],
    }
    conn.close()
    _stats_cache['t'] = now
    _stats_cache['data'] = stats
    return stats

@app.before_request
def handle_lang():
    lang = request.args.get('lang')
    if lang in ('ar', 'fr'):
        session['lang'] = lang
        referrer = request.referrer or url_for('index')
        from urllib.parse import urlparse, urlunparse, urlencode, parse_qs
        parsed = urlparse(referrer)
        params = parse_qs(parsed.query)
        params.pop('lang', None)
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        if new_url and new_url != referrer:
            return redirect(new_url)

def dt_fmt(value, fmt='%Y-%m-%d %H:%M'):
    if not value:
        return ''
    if isinstance(value, datetime):
        return value.strftime(fmt)
    return str(value)[:16]

app.add_template_filter(dt_fmt, 'dt_fmt')

@app.context_processor
def inject_globals():
    ctx = {
        'wilayas': ALGERIAN_WILAYAS,
        'wilaya_slugs': WILAYA_SLUGS,
        'categories': JOB_CATEGORIES,
        'contract_types': CONTRACT_TYPES,
        'now': datetime.now(),
        'stats': get_stats(),
    }

    if 'user_id' in session:
        conn = get_db()
        ctx['unread_count'] = get_unread_count(session['user_id'])
        user = conn.execute('SELECT COALESCE(wallet_balance,0) as wallet_balance, user_type FROM users WHERE id = %s', (session['user_id'],)).fetchone()
        if user:
            ctx['wallet_balance'] = user['wallet_balance']
            if user['user_type'] == 'employer' or session.get('user_type') == 'employer':
                price = conn.execute('SELECT value FROM settings WHERE key = %s', ('job_price',)).fetchone()
                ctx['job_price'] = int(price['value']) if price else JOB_PRICE
        conn.close()
    return ctx

@app.route('/')
def index():
    conn = get_db()
    featured = conn.execute('''
        SELECT j.*, e.company_name, u.full_name, u.avatar_url
        FROM jobs j JOIN employers e ON j.employer_id = e.id
        JOIN users u ON e.user_id = u.id
        WHERE j.status = 'approved' AND j.is_featured = 1
        ORDER BY j.created_at DESC LIMIT 6
    ''').fetchall()

    recent = conn.execute('''
        SELECT j.*, e.company_name, u.full_name, u.avatar_url
        FROM jobs j JOIN employers e ON j.employer_id = e.id
        JOIN users u ON e.user_id = u.id
        WHERE j.status = 'approved'
        ORDER BY j.created_at DESC LIMIT 12
    ''').fetchall()

    urgent = conn.execute('''
        SELECT j.*, e.company_name, u.full_name, u.avatar_url
        FROM jobs j JOIN employers e ON j.employer_id = e.id
        JOIN users u ON e.user_id = u.id
        WHERE j.status = 'approved' AND j.is_urgent = 1
        ORDER BY j.created_at DESC LIMIT 6
    ''').fetchall()

    top_employers = conn.execute('''
        SELECT e.*, u.full_name, u.email, u.avatar_url,
            (SELECT COUNT(*) FROM jobs WHERE employer_id = e.id AND status = 'approved') as job_count
        FROM employers e JOIN users u ON e.user_id = u.id
        ORDER BY job_count DESC LIMIT 8
    ''').fetchall()

    banners = conn.execute('''
        SELECT * FROM banners WHERE is_active = 1
        AND (ends_at IS NULL OR ends_at > CURRENT_TIMESTAMP)
        ORDER BY sort_order ASC, id DESC
    ''').fetchall()

    conn.close()
    return render_template('index.html', featured=featured, recent=recent, urgent=urgent, top_employers=top_employers, banners=banners)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def register():
    if request.method == 'POST':
        full_name = request.form['full_name'].strip()
        email = request.form['email'].strip().lower()
        phone = request.form['phone'].strip()
        password = request.form['password']
        confirm_password = request.form.get('confirm_password', '')
        user_type = request.form['user_type']
        if user_type not in ('worker', 'employer'):
            flash('نوع الحساب غير صالح', 'danger')
            return render_template('register.html')

        if password != confirm_password:
            flash('كلمة المرور غير متطابقة', 'danger')
            return render_template('register.html')

        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('البريد الإلكتروني غير صحيح', 'danger')
            return render_template('register.html')

        if len(password) < 8:
            flash('كلمة المرور يجب أن تكون 8 أحرف على الأقل', 'danger')
            return render_template('register.html')

        conn = get_db()
        existing = conn.execute('SELECT id FROM users WHERE email = %s', (email,)).fetchone()
        if existing:
            flash('البريد الإلكتروني مستخدم بالفعل', 'danger')
            return render_template('register.html')

        hashed = generate_password_hash(password)
        cur = conn.execute(
            'INSERT INTO users (full_name, email, phone, password, user_type) VALUES (%s, %s, %s, %s, %s) RETURNING id',
            (full_name, email, phone, hashed, user_type)
        )
        user_id = cur.fetchone()['id']

        if user_type == 'worker':
            conn.execute('INSERT INTO workers (user_id) VALUES (%s)', (user_id,))
        else:
            company_name = request.form.get('company_name', '').strip() or full_name
            conn.execute('UPDATE users SET wallet_balance = %s WHERE id = %s', (0, user_id))
            conn.execute('INSERT INTO employers (user_id, company_name) VALUES (%s, %s)', (user_id, company_name))

        conn.commit()
        conn.close()

        notify(user_id, 'مرحباً بك في تسهيل!', f'أهلاً {full_name}، تم إنشاء حسابك بنجاح. نتمنى لك تجربة موفقة!', 'success', '/profile')

        flash('تم التسجيل بنجاح! يمكنك تسجيل الدخول الآن', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login/google')
def google_login():
    if not GOOGLE_CLIENT_ID:
        flash('تسجيل الدخول بواسطة Google غير متاح حالياً', 'warning')
        return redirect(url_for('login'))
    redirect_uri = f'{BASE_URL}/login/google/callback' if BASE_URL != 'http://localhost:8080' else url_for('google_callback', _external=True)
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid email profile',
        'access_type': 'online',
        'state': state,
    }
    from urllib.parse import urlencode
    url = f'https://accounts.google.com/o/oauth2/auth?{urlencode(params)}'
    return redirect(url)

@app.route('/login/google/callback')
def google_callback():
    code = request.args.get('code')
    error = request.args.get('error')
    if not request.args.get('state') or request.args.get('state') != session.get('oauth_state'):
        flash('فشل التحقق من تسجيل الدخول، أعد المحاولة', 'danger')
        return redirect(url_for('login'))
    session.pop('oauth_state', None)
    if error or not code:
        flash('تم إلغاء تسجيل الدخول بواسطة Google', 'warning')
        return redirect(url_for('login'))
    import requests as req
    redirect_uri = f'{BASE_URL}/login/google/callback' if BASE_URL != 'http://localhost:8080' else url_for('google_callback', _external=True)
    token_data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
    }
    resp = req.post('https://oauth2.googleapis.com/token', data=token_data).json()
    if 'access_token' not in resp:
        flash('فشل تسجيل الدخول بواسطة Google', 'danger')
        return redirect(url_for('login'))
    headers = {'Authorization': f'Bearer {resp["access_token"]}'}
    user_info = req.get('https://www.googleapis.com/oauth2/v2/userinfo', headers=headers).json()
    email = user_info.get('email', '').lower()
    name = user_info.get('name', 'مستخدم Google')
    if not email:
        flash('لم نتمكن من الحصول على بريدك الإلكتروني من Google', 'danger')
        return redirect(url_for('login'))
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE email = %s', (email,)).fetchone()
    if user:
        if user['user_type'] == 'admin':
            conn.close()
            flash('لا يمكن تسجيل الدخول بحساب المشرف عبر Google', 'danger')
            return redirect(url_for('login'))
    else:
        import re
        cur = conn.execute(
            'INSERT INTO users (full_name, email, password, user_type, is_verified) VALUES (%s, %s, %s, %s, %s) RETURNING id',
            (name, email, generate_password_hash(str(uuid.uuid4())), 'worker', 1)
        )
        user_id = cur.fetchone()['id']
        conn.execute('INSERT INTO workers (user_id) VALUES (%s)', (user_id,))
        conn.commit()
        user = conn.execute('SELECT * FROM users WHERE id = %s', (user_id,)).fetchone()
        notify(user_id, 'مرحباً بك في تسهيل!', f'أهلاً {name}، تم إنشاء حسابك عبر Google بنجاح!', 'success', '/profile')
    conn.close()
    session.permanent = True
    session['user_id'] = user['id']
    session['full_name'] = user['full_name']
    session['user_type'] = user['user_type']
    session['is_verified'] = user['is_verified']
    session['avatar_url'] = get_avatar_url(user)
    flash(f'مرحباً {user["full_name"]}!', 'success')
    return redirect(url_for('index'))

@app.route('/login/facebook')
def facebook_login():
    if not FACEBOOK_APP_ID:
        flash('تسجيل الدخول بواسطة Facebook غير متاح حالياً', 'warning')
        return redirect(url_for('login'))
    redirect_uri = url_for('facebook_callback', _external=True)
    state = secrets.token_urlsafe(16)
    session['oauth_state'] = state
    params = {
        'client_id': FACEBOOK_APP_ID,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'email,public_profile',
        'state': state,
    }
    from urllib.parse import urlencode
    url = f'https://www.facebook.com/v19.0/dialog/oauth?{urlencode(params)}'
    return redirect(url)

@app.route('/login/facebook/callback')
def facebook_callback():
    code = request.args.get('code')
    error = request.args.get('error')
    if not request.args.get('state') or request.args.get('state') != session.get('oauth_state'):
        flash('فشل التحقق من تسجيل الدخول، أعد المحاولة', 'danger')
        return redirect(url_for('login'))
    session.pop('oauth_state', None)
    if error or not code:
        flash('تم إلغاء تسجيل الدخول بواسطة Facebook', 'warning')
        return redirect(url_for('login'))
    import requests as req
    redirect_uri = url_for('facebook_callback', _external=True)
    token_data = {
        'client_id': FACEBOOK_APP_ID,
        'client_secret': FACEBOOK_APP_SECRET,
        'redirect_uri': redirect_uri,
        'code': code,
    }
    resp = req.get('https://graph.facebook.com/v19.0/oauth/access_token', params=token_data).json()
    if 'access_token' not in resp:
        flash('فشل تسجيل الدخول بواسطة Facebook', 'danger')
        return redirect(url_for('login'))
    headers = {'Authorization': f'Bearer {resp["access_token"]}'}
    user_info = req.get('https://graph.facebook.com/me?fields=id,name,email', headers=headers).json()
    email = user_info.get('email', '').lower()
    name = user_info.get('name', 'مستخدم Facebook')
    if not email:
        flash('لم نتمكن من الحصول على بريدك الإلكتروني من Facebook', 'danger')
        return redirect(url_for('login'))
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE email = %s', (email,)).fetchone()
    if user:
        if user['user_type'] == 'admin':
            conn.close()
            flash('لا يمكن تسجيل الدخول بحساب المشرف عبر Facebook', 'danger')
            return redirect(url_for('login'))
    else:
        import re
        cur = conn.execute(
            'INSERT INTO users (full_name, email, password, user_type, is_verified) VALUES (%s, %s, %s, %s, %s) RETURNING id',
            (name, email, generate_password_hash(str(uuid.uuid4())), 'worker', 1)
        )
        user_id = cur.fetchone()['id']
        conn.execute('INSERT INTO workers (user_id) VALUES (%s)', (user_id,))
        conn.commit()
        user = conn.execute('SELECT * FROM users WHERE id = %s', (user_id,)).fetchone()
        notify(user_id, 'مرحباً بك في تسهيل!', f'أهلاً {name}، تم إنشاء حسابك عبر Facebook بنجاح!', 'success', '/profile')
    conn.close()
    session.permanent = True
    session['user_id'] = user['id']
    session['full_name'] = user['full_name']
    session['user_type'] = user['user_type']
    session['is_verified'] = user['is_verified']
    session['avatar_url'] = get_avatar_url(user)
    flash(f'مرحباً {user["full_name"]}!', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = %s', (email,)).fetchone()
        conn.close()

        if user and dict(user).get('is_active', 1) and check_password_hash(user['password'], password):
            session.clear()
            session.permanent = True
            session['csrf_token'] = secrets.token_hex(32)
            session['user_id'] = user['id']
            session['full_name'] = user['full_name']
            session['user_type'] = user['user_type']
            session['is_verified'] = user['is_verified']
            session['avatar_url'] = get_avatar_url(user)
            flash(f'مرحباً {user["full_name"]}!', 'success')

            if user['user_type'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('index'))
        else:
            flash('البريد الإلكتروني أو كلمة المرور غير صحيحة', 'danger')

    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        conn = get_db()
        user = conn.execute('SELECT id, full_name FROM users WHERE email = %s', (email,)).fetchone()
        if user:
            token = str(uuid.uuid4())
            expires = (datetime.now() + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
            conn.execute('DELETE FROM reset_tokens WHERE user_id = %s', (user['id'],))
            conn.execute(
                'INSERT INTO reset_tokens (user_id, token, expires_at) VALUES (%s, %s, %s)',
                (user['id'], token, expires)
            )
            conn.commit()
            conn.close()
            reset_link = url_for('reset_password', token=token, _external=True)
            send_email(
                email,
                'إعادة تعيين كلمة المرور - تسهيل',
                f'''
    مرحباً {user['full_name']}،

    لقد تلقينا طلباً لإعادة تعيين كلمة المرور لحسابك في منصة تسهيل.

    اضغط على الرابط أدناه لإعادة تعيين كلمة المرور:
    {reset_link}

    إذا لم تطلب إعادة تعيين كلمة المرور، تجاهل هذه الرسالة.

    شكراً،
    فريق تسهيل
                ''',
                f'''
    <html><body style="font-family:Cairo,sans-serif;background:#f9fafb;padding:32px">
    <div style="max-width:480px;margin:auto;background:#fff;border-radius:16px;padding:32px;box-shadow:0 4px 12px rgba(0,0,0,0.1)">
    <div style="text-align:center;margin-bottom:24px"><span style="font-size:1.5rem;font-weight:800;color:#059669">تسهيل</span></div>
    <h2 style="color:#1f2937;font-size:1.2rem;margin-bottom:16px">إعادة تعيين كلمة المرور</h2>
    <p style="color:#6b7280;line-height:1.7">مرحباً {user['full_name']}،</p>
    <p style="color:#6b7280;line-height:1.7">لقد تلقينا طلباً لإعادة تعيين كلمة المرور لحسابك. اضغط على الزر أدناه لإكمال العملية:</p>
    <div style="text-align:center;margin:24px 0">
    <a href="{reset_link}" style="display:inline-block;padding:12px 32px;background:linear-gradient(135deg,#059669,#34d399);color:#fff;text-decoration:none;border-radius:8px;font-weight:700">إعادة تعيين كلمة المرور</a>
    </div>
    <p style="color:#9ca3af;font-size:0.85rem">إذا لم تطلب إعادة التعيين، تجاهل هذه الرسالة.</p>
    <p style="color:#9ca3af;font-size:0.85rem;margin-top:16px">فريق تسهيل</p>
    </div></body></html>
                ''',
            )
        else:
            conn.close()
        flash('إذا كان البريد الإلكتروني مسجلاً، ستتلقى رابط إعادة التعيين', 'success')
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db()
    now = 'NOW()' if os.environ.get('DATABASE_URL') else "datetime('now')"
    record = conn.execute(f'''
        SELECT r.*, u.email FROM reset_tokens r
        JOIN users u ON r.user_id = u.id
        WHERE r.token = %s AND r.used = 0 AND r.expires_at > {now}
    ''', (token,)).fetchone()
    if not record:
        conn.close()
        flash('رابط إعادة التعيين غير صالح أو منتهي الصلاحية', 'danger')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form.get('confirm_password', '')
        if password != confirm:
            flash('كلمة المرور غير متطابقة', 'danger')
            return render_template('reset_password.html', token=token)
        if len(password) < 6:
            flash('كلمة المرور يجب أن تكون 6 أحرف على الأقل', 'danger')
            return render_template('reset_password.html', token=token)
        hashed = generate_password_hash(password)
        conn.execute('UPDATE users SET password = %s WHERE id = %s', (hashed, record['user_id']))
        conn.execute('UPDATE reset_tokens SET used = 1 WHERE id = %s', (record['id'],))
        conn.commit()
        conn.close()
        flash('تم تغيير كلمة المرور بنجاح. يمكنك تسجيل الدخول الآن', 'success')
        return redirect(url_for('login'))
    conn.close()
    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    session.clear()
    flash('تم تسجيل الخروج بنجاح', 'info')
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    conn = get_db()
    if session['user_type'] == 'worker':
        user = conn.execute('''
            SELECT u.*, w.* FROM users u
            JOIN workers w ON w.user_id = u.id WHERE u.id = %s
        ''', (session['user_id'],)).fetchone()

        if request.method == 'POST':
            conn.execute('''
                UPDATE workers SET skills=%s, experience_years=%s, experience_level=%s,
                education=%s, city=%s, wilaya=%s, about=%s, availability=%s,
                expected_salary=%s, linkedin_url=%s, portfolio_url=%s
                WHERE user_id=%s
            ''', (
                request.form['skills'], request.form.get('experience_years', 0, int),
                request.form['experience_level'], request.form['education'],
                request.form['city'], request.form['wilaya'], request.form['about'],
                request.form['availability'], request.form.get('expected_salary', type=int),
                request.form.get('linkedin_url', ''), request.form.get('portfolio_url', ''),
                session['user_id']
            ))
            conn.commit()
            conn.close()
            flash('تم تحديث الملف الشخصي', 'success')
            return redirect(url_for('profile'))
        conn.close()
        return render_template('profile_worker.html', user=user)

    else:
        user = conn.execute('''
            SELECT u.*, e.* FROM users u
            JOIN employers e ON e.user_id = u.id WHERE u.id = %s
        ''', (session['user_id'],)).fetchone()

        if request.method == 'POST':
            conn.execute('''
                UPDATE employers SET company_name=%s, company_description=%s,
                company_website=%s, company_size=%s, company_sector=%s,
                city=%s, wilaya=%s, address=%s
                WHERE user_id=%s
            ''', (
                request.form['company_name'], request.form['company_description'],
                request.form['company_website'], request.form['company_size'],
                request.form['company_sector'], request.form['city'],
                request.form['wilaya'], request.form['address'],
                session['user_id']
            ))
            conn.commit()
            conn.close()
            flash('تم تحديث الملف الشخصي', 'success')
            return redirect(url_for('profile'))
        conn.close()
        return render_template('profile_employer.html', user=user)

@app.route('/upload-avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        flash('لم يتم اختيار ملف', 'danger')
        return redirect(url_for('profile'))
    file = request.files['avatar']
    if file.filename == '':
        flash('لم يتم اختيار ملف', 'danger')
        return redirect(url_for('profile'))
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    if ext not in ALLOWED_EXTENSIONS:
        flash('الصيغة غير مدعومة. يرجى اختيار PNG, JPG, GIF أو WebP', 'danger')
        return redirect(url_for('profile'))
    if not validate_image(file):
        flash('الملف ليس صورة صالحة', 'danger')
        return redirect(url_for('profile'))
    file.seek(0, os.SEEK_END)
    if file.tell() > AVATAR_MAX_SIZE:
        flash('حجم الصورة كبير جداً. الحد الأقصى 2 ميغابايت', 'danger')
        return redirect(url_for('profile'))
    file.seek(0)
    filename = f'avatar_{session["user_id"]}_{int(time.time())}.{ext}'
    file.save(os.path.join(STORAGE_ROOT, 'uploads', 'avatars', filename))
    avatar_url = url_for('static', filename=f'uploads/avatars/{filename}')
    conn = get_db()
    conn.execute('UPDATE users SET avatar_url = %s WHERE id = %s', (avatar_url, session['user_id']))
    conn.commit()
    conn.close()
    session['avatar_url'] = avatar_url
    flash('تم تحديث الصورة الشخصية بنجاح!', 'success')
    return redirect(url_for('profile'))

@app.route('/jobs')
def jobs():
    conn = get_db()
    base_query = '''
        FROM jobs j JOIN employers e ON j.employer_id = e.id
        JOIN users u ON e.user_id = u.id
        WHERE j.status = 'approved'
    '''
    params = []

    search = request.args.get('search', '').strip()
    wilaya = request.args.get('wilaya', '').strip()
    category = request.args.get('category', '').strip()
    contract = request.args.get('contract', '').strip()
    experience = request.args.get('experience', '').strip()
    salary_min = request.args.get('salary_min', '').strip()
    sort = request.args.get('sort', 'newest').strip()
    try:
        page = int(request.args.get('page', '1'))
    except (ValueError, TypeError):
        page = 1
    if page < 1:
        page = 1
    per_page = 12

    where = ''
    if search:
        where += " AND (j.title LIKE %s OR j.description LIKE %s OR e.company_name LIKE %s)"
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
    if wilaya:
        where += " AND j.wilaya = %s"
        params.append(wilaya)
    if category:
        where += " AND j.category = %s"
        params.append(category)
    if contract:
        where += " AND j.contract_type = %s"
        params.append(contract)
    if experience:
        where += " AND j.experience_level = %s"
        params.append(experience)
    if salary_min:
        try:
            salary_min_int = int(salary_min)
        except (ValueError, TypeError):
            salary_min_int = None
        if salary_min_int is not None:
            where += " AND j.salary_max >= %s"
            params.append(salary_min_int)

    count_row = conn.execute(f'SELECT COUNT(*) as c {base_query}{where}', params).fetchone()
    total = count_row['c']
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)

    if sort == 'oldest':
        order = " ORDER BY j.created_at ASC"
    elif sort == 'salary':
        order = " ORDER BY j.salary_max DESC NULLS LAST"
    else:
        order = " ORDER BY j.created_at DESC"

    offset = (page - 1) * per_page
    jobs = conn.execute(f'''
        SELECT j.*, e.company_name, e.company_logo, u.full_name, u.avatar_url
        {base_query}{where}{order} LIMIT %s OFFSET %s
    ''', params + [per_page, offset]).fetchall()
    conn.close()
    return render_template('jobs.html', jobs=jobs, search=search, wilaya=wilaya,
                         category=category, contract=contract, experience=experience,
                         sort=sort, page=page, total_pages=total_pages)

@app.route('/wilaya/<slug>')
def wilaya_jobs(slug):
    name = WILAYA_SLUGS.get(slug)
    if not name:
        abort(404)
    conn = get_db()
    jobs = conn.execute('''
        SELECT j.*, e.company_name, u.avatar_url FROM jobs j
        JOIN employers e ON j.employer_id = e.id
        JOIN users u ON e.user_id = u.id
        WHERE j.status = 'approved' AND j.wilaya = %s
        ORDER BY j.created_at DESC
    ''', (name,)).fetchall()
    conn.close()
    return render_template('wilaya.html', jobs=jobs, wilaya_name=name, wilaya_slug=slug)

@app.route('/health')
def health():
    try:
        conn = get_db()
        conn.execute('SELECT 1').fetchone()
        conn.close()
        return jsonify({'status': 'ok'})
    except Exception:
        return jsonify({'status': 'error'}), 500

@app.route('/_version')
def version():
    import os
    sha = os.environ.get('RAILWAY_GIT_COMMIT_SHA', 'local-dev')[:7]
    return f'<pre>GIT: {sha}\nSESSION_PERMANENT: {app.config.get("SESSION_PERMANENT")}\nPERMANENT_LIFETIME: {app.config.get("PERMANENT_SESSION_LIFETIME")}</pre>'

@app.route('/jobs/<int:job_id>')
def job_detail(job_id):
    with get_db() as conn:
        job = conn.execute('''
            SELECT j.*, e.company_name, e.company_size, e.company_sector,
                   e.city as e_city, e.wilaya as e_wilaya,
                   e.company_description, e.company_website, e.company_logo,
                    u.full_name, u.phone, u.email, u.avatar_url
            FROM jobs j JOIN employers e ON j.employer_id = e.id
            JOIN users u ON e.user_id = u.id
            WHERE j.id = %s
        ''', (job_id,)).fetchone()

        if not job:
            flash('الوظيفة غير موجودة', 'danger')
            return redirect(url_for('jobs'))

        if job['status'] not in ('approved', 'pending'):
            flash('الوظيفة غير موجودة', 'danger')
            return redirect(url_for('jobs'))

        if job['status'] == 'pending':
            owner_id = conn.execute(
                'SELECT user_id FROM employers WHERE id = %s',
                (job['employer_id'],)
            ).fetchone()
            uid = session.get('user_id')
            if not owner_id or not uid or owner_id['user_id'] != uid:
                flash('الوظيفة غير موجودة', 'danger')
                return redirect(url_for('jobs'))

        conn.execute('UPDATE jobs SET views_count = views_count + 1 WHERE id = %s', (job_id,))

        similar = conn.execute('''
            SELECT j.*, e.company_name, u.avatar_url FROM jobs j
            JOIN employers e ON j.employer_id = e.id
            JOIN users u ON e.user_id = u.id
            WHERE j.category IS NOT NULL AND j.category = %s AND j.id != %s AND j.status = 'approved'
            LIMIT 4
        ''', (job['category'], job_id)).fetchall()

        has_applied = False
        is_saved = False
        if 'user_id' in session and session['user_type'] == 'worker':
            worker = conn.execute('SELECT id FROM workers WHERE user_id = %s', (session['user_id'],)).fetchone()
            if worker:
                has_applied = bool(conn.execute(
                    'SELECT id FROM applications WHERE job_id = %s AND worker_id = %s',
                    (job_id, worker['id'])
                ).fetchone())
                is_saved = bool(conn.execute(
                    'SELECT id FROM saved_jobs WHERE job_id = %s AND worker_id = %s',
                    (job_id, worker['id'])
                ).fetchone())

        conn.commit()

    employment_map = {
        'دوام كامل': 'FULL_TIME', 'عقد دائم': 'FULL_TIME', 'full': 'FULL_TIME', 'full-time': 'FULL_TIME',
        'دوام جزئي': 'PART_TIME', 'جزئي': 'PART_TIME', 'part': 'PART_TIME', 'part-time': 'PART_TIME',
        'عقد': 'CONTRACTOR', 'contract': 'CONTRACTOR',
        'مؤقت': 'TEMPORARY', 'temp': 'TEMPORARY',
        'تدريب': 'INTERN', 'intern': 'INTERN',
    }
    ct = (job['contract_type'] or '').strip().lower()
    employment_type = 'OTHER'
    for key, val in employment_map.items():
        if key in ct:
            employment_type = val
            break

    job_jsonld = {
        '@context': 'https://schema.org',
        '@type': 'JobPosting',
        'title': job['title'],
        'description': (job['description'] or '')[:500],
        'datePosted': job['created_at'].strftime('%Y-%m-%d') if hasattr(job['created_at'], 'strftime') else str(job['created_at'])[:10],
        'employmentType': employment_type,
        'hiringOrganization': {'@type': 'Organization', 'name': job['company_name']},
        'jobLocation': {
            '@type': 'Place',
            'address': {
                '@type': 'PostalAddress',
                'addressLocality': job['city'] or job['wilaya'] or '',
                'addressRegion': job['wilaya'] or '',
                'addressCountry': 'DZ',
            }
        },
        'url': request.url_root.rstrip('/') + url_for('job_detail', job_id=job['id']),
    }
    if job['salary_min'] or job['salary_max']:
        job_jsonld['baseSalary'] = {
            '@type': 'MonetaryAmount',
            'currency': 'DZD',
            'value': {
                '@type': 'QuantitativeValue',
                'minValue': job['salary_min'] or 0,
                'maxValue': job['salary_max'] or job['salary_min'],
                'unitText': 'MONTH',
            }
        }
    if job['company_website']:
        job_jsonld['hiringOrganization']['sameAs'] = job['company_website']

    return render_template('job_detail.html', job=job, similar=similar, has_applied=has_applied, is_saved=is_saved, job_jsonld=job_jsonld)

@app.route('/jobs/create', methods=['GET', 'POST'])
@employer_required
def create_job():
    if request.method == 'POST':
        conn = get_db()
        user = conn.execute('SELECT COALESCE(wallet_balance,0) as wallet_balance FROM users WHERE id = %s', (session['user_id'],)).fetchone()
        price_row = conn.execute('SELECT value FROM settings WHERE key = %s', ('job_price',)).fetchone()
        job_price = int(price_row['value']) if price_row else JOB_PRICE

        if user['wallet_balance'] < job_price:
            flash(f'رصيدك غير كافٍ. تحتاج إلى {job_price} دج لنشر وظيفة. رصيدك الحالي: {user["wallet_balance"]} دج', 'danger')
            conn.close()
            return redirect(url_for('employer_wallet'))

        employer = conn.execute('SELECT id FROM employers WHERE user_id = %s', (session['user_id'],)).fetchone()
        new_balance = user['wallet_balance'] - job_price
        conn.execute('UPDATE users SET wallet_balance = %s WHERE id = %s', (new_balance, session['user_id']))
        conn.execute('''
            INSERT INTO transactions (user_id, type, amount, balance_before, balance_after, description, reference_type, status)
            VALUES (%s, 'debit', %s, %s, %s, %s, 'job_post', 'completed')
        ''', (session['user_id'], job_price, user['wallet_balance'], new_balance, 'نشر وظيفة'))
        conn.execute('''
            INSERT INTO jobs (employer_id, title, description, requirements, responsibilities, benefits, contract_type, experience_level, city, wilaya, category, salary_min, salary_max, positions_count, is_urgent)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            employer['id'], request.form['title'], request.form['description'],
            request.form.get('requirements', ''), request.form.get('responsibilities', ''),
            request.form.get('benefits', ''), request.form['contract_type'],
            request.form['experience_level'], request.form['city'], request.form['wilaya'],
            request.form['category'],
            request.form.get('salary_min', type=int), request.form.get('salary_max', type=int),
            request.form.get('positions_count', 1, int),
            1 if request.form.get('is_urgent') else 0
        ))
        conn.commit()
        conn.close()
        flash('تم نشر الوظيفة وإرسالها للمراجعة بنجاح!', 'success')
        return redirect(url_for('my_jobs'))

    return render_template('job_form.html')

@app.route('/my-jobs')
@employer_required
def my_jobs():
    conn = get_db()
    employer = conn.execute('SELECT id FROM employers WHERE user_id = %s', (session['user_id'],)).fetchone()
    jobs = conn.execute('''
        SELECT j.*, (SELECT COUNT(*) FROM applications WHERE job_id = j.id) as app_count
        FROM jobs j WHERE j.employer_id = %s
        ORDER BY j.created_at DESC
    ''', (employer['id'],)).fetchall()
    conn.close()
    return render_template('my_jobs.html', jobs=jobs)

@app.route('/jobs/<int:job_id>/toggle', methods=['POST'])
@employer_required
def toggle_job(job_id):
    conn = get_db()
    employer = conn.execute('SELECT id FROM employers WHERE user_id = %s', (session['user_id'],)).fetchone()
    job = conn.execute('SELECT status FROM jobs WHERE id = %s AND employer_id = %s', (job_id, employer['id'])).fetchone()
    if job and job['status'] == 'approved':
        conn.execute("UPDATE jobs SET status = 'closed' WHERE id = %s", (job_id,))
    elif job and job['status'] == 'closed':
        conn.execute("UPDATE jobs SET status = 'approved' WHERE id = %s", (job_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('my_jobs'))

@app.route('/jobs/<int:job_id>/delete', methods=['POST'])
@employer_required
def delete_job(job_id):
    conn = get_db()
    employer = conn.execute('SELECT id FROM employers WHERE user_id = %s', (session['user_id'],)).fetchone()
    conn.execute('DELETE FROM jobs WHERE id = %s AND employer_id = %s', (job_id, employer['id']))
    conn.commit()
    conn.close()
    flash('تم حذف الوظيفة', 'info')
    return redirect(url_for('my_jobs'))

@app.route('/jobs/<int:job_id>/apply', methods=['POST'])
@worker_required
def apply_job(job_id):
    conn = get_db()
    worker = conn.execute('SELECT id FROM workers WHERE user_id = %s', (session['user_id'],)).fetchone()
    existing = conn.execute('SELECT id FROM applications WHERE job_id = %s AND worker_id = %s', (job_id, worker['id'])).fetchone()
    if existing:
        flash('لقد تقدمت لهذه الوظيفة مسبقاً', 'warning')
    else:
        conn.execute('INSERT INTO applications (job_id, worker_id, cover_letter) VALUES (%s, %s, %s)',
                    (job_id, worker['id'], request.form.get('cover_letter', '')))
        conn.execute('UPDATE jobs SET applications_count = applications_count + 1 WHERE id = %s', (job_id,))

        job = conn.execute('SELECT employer_id, title FROM jobs WHERE id = %s', (job_id,)).fetchone()
        employer_user = conn.execute('SELECT user_id FROM employers WHERE id = %s', (job['employer_id'],)).fetchone()
        notify(employer_user['user_id'], 'طلب توظيف جديد',
               f'تم استلام طلب جديد على وظيفة "{job["title"]}"', 'info', f'/applications', conn=conn)
        flash('تم التقديم على الوظيفة بنجاح!', 'success')
    conn.commit()
    conn.close()
    return redirect(url_for('job_detail', job_id=job_id))

@app.route('/jobs/<int:job_id>/save', methods=['POST'])
@worker_required
def save_job(job_id):
    conn = get_db()
    worker = conn.execute('SELECT id FROM workers WHERE user_id = %s', (session['user_id'],)).fetchone()
    existing = conn.execute('SELECT id FROM saved_jobs WHERE job_id = %s AND worker_id = %s', (job_id, worker['id'])).fetchone()
    if existing:
        conn.execute('DELETE FROM saved_jobs WHERE id = %s', (existing['id'],))
        flash('تم إزالة الوظيفة من المحفوظات', 'info')
    else:
        conn.execute('INSERT INTO saved_jobs (job_id, worker_id) VALUES (%s, %s)', (job_id, worker['id']))
        flash('تم حفظ الوظيفة', 'success')
    conn.commit()
    conn.close()
    return redirect(url_for('job_detail', job_id=job_id))

@app.route('/requests/create', methods=['POST'])
@worker_required
def create_request():
    rtype = request.form.get('type', 'request')
    if rtype not in ('request', 'appointment', 'info'):
        flash('نوع الطلب غير صالح', 'danger')
        return redirect(request.referrer or url_for('index'))

    conn = get_db()
    worker = conn.execute('SELECT id FROM workers WHERE user_id = %s', (session['user_id'],)).fetchone()
    if not worker:
        conn.close()
        flash('الرجاء إكمال ملفك الشخصي أولاً', 'warning')
        return redirect(url_for('profile'))

    employer_id = request.form.get('employer_id', type=int)
    job_id = request.form.get('job_id', type=int)
    subject = (request.form.get('subject') or '').strip()
    message = (request.form.get('message') or '').strip()
    preferred_date = (request.form.get('preferred_date') or '').strip()

    if rtype == 'info':
        employer_id = None
    else:
        if not employer_id:
            conn.close()
            flash('الرجاء اختيار المؤسسة', 'danger')
            return redirect(request.referrer or url_for('index'))

    if not message:
        conn.close()
        flash('الرجاء كتابة الرسالة', 'danger')
        return redirect(request.referrer or url_for('index'))

    conn.execute('''
        INSERT INTO requests (worker_id, type, employer_id, job_id, subject, message, preferred_date)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    ''', (worker['id'], rtype, employer_id, job_id, subject, message, preferred_date))

    if rtype != 'info' and employer_id:
        employer = conn.execute('SELECT user_id FROM employers WHERE id = %s', (employer_id,)).fetchone()
        if employer:
            type_label = {'request': 'طلب جديد من موظف', 'appointment': 'حجز موعد جديد'}.get(rtype, 'طلب جديد')
            notify(employer['user_id'], type_label, subject or message[:100], 'info', '/employer/requests', conn=conn)

    conn.commit()
    conn.close()

    type_msg = {'request': 'تم إرسال طلبك إلى رب العمل بنجاح',
                'appointment': 'تم حجز الموعد بنجاح',
                'info': 'تم إرسال طلبك إلى الإدارة بنجاح'}.get(rtype, 'تم إرسال الطلب')
    flash(type_msg, 'success')
    return redirect(request.referrer or url_for('my_requests'))

@app.route('/my-requests')
@worker_required
def my_requests():
    conn = get_db()
    worker = conn.execute('SELECT id FROM workers WHERE user_id = %s', (session['user_id'],)).fetchone()
    reqs = conn.execute('''
        SELECT r.*, e.company_name, j.title as job_title
        FROM requests r
        LEFT JOIN employers e ON r.employer_id = e.id
        LEFT JOIN jobs j ON r.job_id = j.id
        WHERE r.worker_id = %s
        ORDER BY r.created_at DESC
    ''', (worker['id'],)).fetchall()
    conn.close()
    return render_template('my_requests.html', reqs=reqs)

@app.route('/requests/<int:req_id>/cancel', methods=['POST'])
@worker_required
def cancel_request(req_id):
    conn = get_db()
    worker = conn.execute('SELECT id FROM workers WHERE user_id = %s', (session['user_id'],)).fetchone()
    conn.execute("UPDATE requests SET status = 'rejected' WHERE id = %s AND worker_id = %s AND status = 'pending'",
                 (req_id, worker['id']))
    conn.commit()
    conn.close()
    flash('تم إلغاء الطلب', 'info')
    return redirect(url_for('my_requests'))

@app.route('/employer/requests')
@employer_required
def employer_requests():
    conn = get_db()
    employer = conn.execute('SELECT id FROM employers WHERE user_id = %s', (session['user_id'],)).fetchone()
    type_filter = request.args.get('type', '')
    status_filter = request.args.get('status', '')

    query = '''
        SELECT r.*, w.experience_level, w.skills, u.full_name, u.phone, u.email, u.avatar_url,
               j.title as job_title
        FROM requests r
        JOIN workers w ON r.worker_id = w.id
        JOIN users u ON w.user_id = u.id
        LEFT JOIN jobs j ON r.job_id = j.id
        WHERE r.employer_id = %s AND r.type != 'info'
    '''
    params = [employer['id']]
    if type_filter:
        query += " AND r.type = %s"
        params.append(type_filter)
    if status_filter:
        query += " AND r.status = %s"
        params.append(status_filter)
    query += " ORDER BY r.created_at DESC"

    reqs = conn.execute(query, params).fetchall()
    conn.close()
    return render_template('employer_requests.html', reqs=reqs, type_filter=type_filter, status_filter=status_filter)

@app.route('/employer/requests/<int:req_id>/<action>', methods=['POST'])
@employer_required
def handle_employer_request(req_id, action):
    if action not in ('accepted', 'rejected', 'completed'):
        return redirect(url_for('employer_requests'))
    conn = get_db()
    employer = conn.execute('SELECT id FROM employers WHERE user_id = %s', (session['user_id'],)).fetchone()
    req = conn.execute('SELECT * FROM requests WHERE id = %s AND employer_id = %s AND type != %s',
                       (req_id, employer['id'], 'info')).fetchone()
    if req:
        conn.execute('UPDATE requests SET status = %s WHERE id = %s', (action, req_id))
        worker = conn.execute('SELECT user_id FROM workers WHERE id = %s', (req['worker_id'],)).fetchone()
        status_text = {'accepted': 'تم قبول طلبك', 'rejected': 'تم رفض طلبك', 'completed': 'تم إتمام طلبك'}
        notify(worker['user_id'], f'تحديث حالة الطلب',
               status_text.get(action, 'تم تحديث حالة طلبك'), 'info', '/my-requests', conn=conn)
    conn.commit()
    conn.close()
    flash('تم تحديث حالة الطلب', 'success')
    return redirect(url_for('employer_requests'))

@app.route('/applications')
@employer_required
def employer_applications():
    conn = get_db()
    employer = conn.execute('SELECT id FROM employers WHERE user_id = %s', (session['user_id'],)).fetchone()
    job_filter = request.args.get('job_id', type=int)
    status_filter = request.args.get('status', '')

    query = '''
        SELECT a.*, j.title as job_title, j.wilaya as job_wilaya,
               u.full_name, u.phone, u.email, u.avatar_url,
               w.skills, w.experience_years, w.experience_level,
               w.education, w.city, w.wilaya, w.about
        FROM applications a
        JOIN jobs j ON a.job_id = j.id
        JOIN workers w ON a.worker_id = w.id
        JOIN users u ON w.user_id = u.id
        WHERE j.employer_id = %s
    '''
    params = [employer['id']]

    if job_filter:
        query += " AND a.job_id = %s"
        params.append(job_filter)
    if status_filter:
        query += " AND a.status = %s"
        params.append(status_filter)

    query += " ORDER BY a.created_at DESC"

    apps = conn.execute(query, params).fetchall()
    jobs_list = conn.execute('SELECT id, title FROM jobs WHERE employer_id = %s', (employer['id'],)).fetchall()
    conn.close()
    return render_template('applications.html', apps=apps, jobs_list=jobs_list)

@app.route('/applications/<int:app_id>/<action>', methods=['POST'])
@employer_required
def handle_application(app_id, action):
    if action not in ('accepted', 'rejected', 'reviewed'):
        return redirect(url_for('employer_applications'))
    conn = get_db()
    app = conn.execute('''
        SELECT a.*, j.title, j.employer_id FROM applications a
        JOIN jobs j ON a.job_id = j.id WHERE a.id = %s
    ''', (app_id,)).fetchone()
    employer = conn.execute('SELECT id FROM employers WHERE user_id = %s', (session['user_id'],)).fetchone()

    if app and employer:
        job = conn.execute('SELECT employer_id FROM jobs WHERE id = %s', (app['job_id'],)).fetchone()
        if job['employer_id'] == employer['id']:
            conn.execute('UPDATE applications SET status = %s WHERE id = %s', (action, app_id))
            worker = conn.execute('SELECT user_id FROM workers WHERE id = %s', (app['worker_id'],)).fetchone()
            status_text = {'accepted': 'تم قبول طلبك', 'rejected': 'تم رفض طلبك', 'reviewed': 'طلبك قيد المراجعة'}
            notify(worker['user_id'], f'تحديث حالة الطلب - {app["title"]}',
                   status_text.get(action, 'تم تحديث حالة طلبك'), 'info', '/my-applications')

    conn.commit()
    conn.close()
    flash('تم تحديث حالة الطلب', 'success')
    return redirect(url_for('employer_applications'))

@app.route('/employer/payment/<request_id>/receipt', methods=['POST'])
@employer_required
def upload_receipt(request_id):
    conn = get_db()
    req = conn.execute('SELECT * FROM payment_requests WHERE reference = %s AND user_id = %s',
                       (request_id, session['user_id'])).fetchone()
    if not req:
        conn.close()
        flash('طلب الدفع غير موجود', 'danger')
        return redirect(url_for('employer_wallet'))
    if 'receipt' not in request.files:
        flash('الرجاء اختيار ملف الإيصال', 'danger')
        return redirect(url_for('payment_status', request_id=request_id))
    file = request.files['receipt']
    if file.filename == '':
        flash('الرجاء اختيار ملف الإيصال', 'danger')
        return redirect(url_for('payment_status', request_id=request_id))
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    if ext not in ALLOWED_RECEIPT_EXTENSIONS:
        flash('صيغة الملف غير مدعومة. يرجى اختيار PNG, JPG, PDF أو WebP', 'danger')
        return redirect(url_for('payment_status', request_id=request_id))
    if ext != 'pdf' and not validate_image(file):
        flash('الملف ليس صورة صالحة', 'danger')
        return redirect(url_for('payment_status', request_id=request_id))
    file.seek(0, os.SEEK_END)
    if file.tell() > RECEIPT_MAX_SIZE:
        flash('حجم الملف كبير جداً. الحد الأقصى 5 ميغابايت', 'danger')
        return redirect(url_for('payment_status', request_id=request_id))
    file.seek(0)
    filename = f'receipt_{request_id}_{uuid.uuid4().hex[:8]}.{ext}'
    receipt_dir = os.path.join(STORAGE_ROOT, 'receipts')
    os.makedirs(receipt_dir, exist_ok=True)
    file.save(os.path.join(receipt_dir, filename))
    conn.execute('UPDATE payment_requests SET receipt_path = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s',
                 (filename, req['id']))
    conn.commit()
    conn.close()
    payer = session.get('full_name', 'مستخدم')
    notify_admin('إيصال دفع مرفوع', f'{payer} رفع إيصال دفع للطلب {request_id} بقيمة {req["amount"]} دج', link='/admin/transactions')
    send_email(ADMIN_EMAIL, f'إيصال دفع مرفوع - تسهيل ({request_id})',
               f'تم رفع إيصال الدفع للطلب {request_id}:\n'
               f'المستخدم: {payer}\nالمبلغ: {req["amount"]} دج\n'
               f'راجعه من لوحة الإدارة: https://talented-respect-production.up.railway.app/admin/transactions')
    flash('تم رفع الإيصال بنجاح. سنقوم بمراجعته قريباً.', 'success')
    return redirect(url_for('payment_status', request_id=request_id))

@app.route('/switch-role/<role>')
@login_required
def switch_role(role):
    if role not in ('worker', 'employer'):
        flash('دور غير صالح', 'danger')
        return redirect(url_for('index'))
    conn = get_db()
    if role == 'employer':
        employer = conn.execute('SELECT id FROM employers WHERE user_id = %s', (session['user_id'],)).fetchone()
        if not employer:
            conn.execute('INSERT INTO employers (user_id, company_name) VALUES (%s, %s)', (session['user_id'], session.get('full_name', 'شركتي')))
            conn.commit()
    elif role == 'worker':
        worker = conn.execute('SELECT id FROM workers WHERE user_id = %s', (session['user_id'],)).fetchone()
        if not worker:
            conn.execute('INSERT INTO workers (user_id) VALUES (%s)', (session['user_id'],))
            conn.commit()
    u = conn.execute('SELECT avatar_url FROM users WHERE id = %s', (session['user_id'],)).fetchone()
    if u: session['avatar_url'] = u['avatar_url'] or ''
    conn.close()
    session['user_type'] = role
    flash(f'تم التبديل إلى وضع {"صاحب عمل" if role == "employer" else "باحث عن عمل"}', 'success')
    return redirect(url_for('index'))

@app.route('/employer/wallet')
@employer_required
def employer_wallet():
    conn = get_db()
    user = conn.execute('SELECT wallet_balance FROM users WHERE id = %s', (session['user_id'],)).fetchone()
    balance = user['wallet_balance'] if user else 0
    price = conn.execute('SELECT value FROM settings WHERE key = %s', ('job_price',)).fetchone()
    job_price = int(price['value']) if price else JOB_PRICE
    transactions = conn.execute('''
        SELECT * FROM transactions WHERE user_id = %s
        ORDER BY created_at DESC LIMIT 50
    ''', (session['user_id'],)).fetchall()
    packages = conn.execute('SELECT * FROM packages WHERE is_active = 1 ORDER BY price ASC').fetchall()
    conn.close()
    return render_template('employer_wallet.html', balance=balance, job_price=job_price,
                         transactions=transactions, packages=packages)

@app.route('/employer/buy-package', methods=['POST'])
@employer_required
def buy_package():
    package_id = request.form.get('package_id', type=int)
    conn = get_db()
    package = conn.execute('SELECT * FROM packages WHERE id = %s AND is_active = 1', (package_id,)).fetchone()
    conn.close()
    if not package:
        flash('الباقة غير موجودة', 'danger')
        return redirect(url_for('employer_wallet'))
    return redirect(url_for('checkout', package_id=package_id))

@app.route('/employer/checkout/<int:package_id>')
@employer_required
def checkout(package_id):
    conn = get_db()
    package = conn.execute('SELECT * FROM packages WHERE id = %s AND is_active = 1', (package_id,)).fetchone()
    if not package:
        conn.close()
        flash('الباقة غير موجودة', 'danger')
        return redirect(url_for('employer_wallet'))
    settings = {row['key']: row['value'] for row in conn.execute("SELECT * FROM settings WHERE key IN ('payment_ccp_rib','payment_ccp_name','payment_phone','payment_baridi')").fetchall()}
    conn.close()
    return render_template('checkout.html', package=package, settings=settings)

@app.route('/employer/payment/create', methods=['POST'])
@employer_required
def create_payment():
    package_id = request.form.get('package_id', type=int)
    amount_manual = request.form.get('amount', type=int)
    conn = get_db()
    if package_id:
        package = conn.execute('SELECT * FROM packages WHERE id = %s AND is_active = 1', (package_id,)).fetchone()
        if not package:
            conn.close()
            flash('الباقة غير موجودة', 'danger')
            return redirect(url_for('employer_wallet'))
        amount = package['price']
        credits = package['credits']
        description = f'شراء باقة: {package["name"]} ({credits} رصيد)'
        ref_pkg_id = package['id']
    elif amount_manual and amount_manual >= 100:
        amount = amount_manual
        credits = 0
        description = f'شحن رصيد بقيمة {amount} دج'
        ref_pkg_id = None
    else:
        conn.close()
        flash('الرجاء تحديد باقة أو إدخال مبلغ صحيح', 'danger')
        return redirect(url_for('employer_wallet'))

    reference = f'TESHIL-{uuid.uuid4().hex[:8].upper()}'
    conn.execute('''
        INSERT INTO payment_requests (user_id, package_id, amount, credits, reference, status)
        VALUES (%s, %s, %s, %s, %s, 'pending')
    ''', (session['user_id'], ref_pkg_id, amount, credits, reference))
    conn.commit()
    conn.close()
    payer = session.get('full_name', 'مستخدم')
    notify_admin('طلب دفع جديد', f'{payer} أنشأ طلب دفع {reference} بقيمة {amount} دج ({description})', link='/admin/transactions')
    send_email(ADMIN_EMAIL, f'طلب دفع جديد - تسهيل ({reference})',
               f'طلب دفع جديد في انتظار المراجعة:\n'
               f'المستخدم: {payer}\nالمرجع: {reference}\nالمبلغ: {amount} دج\n'
               f'الوصف: {description}\n'
               f'راجعه من لوحة الإدارة: https://talented-respect-production.up.railway.app/admin/transactions')
    return redirect(url_for('payment_status', request_id=reference))

@app.route('/employer/payment/<request_id>')
@employer_required
def payment_status(request_id):
    conn = get_db()
    req = conn.execute('''
        SELECT pr.*, p.name as package_name, p.credits as package_credits
        FROM payment_requests pr LEFT JOIN packages p ON pr.package_id = p.id
        WHERE pr.reference = %s AND pr.user_id = %s
    ''', (request_id, session['user_id'])).fetchone()
    conn.close()
    if not req:
        flash('طلب الدفع غير موجود', 'danger')
        return redirect(url_for('employer_wallet'))
    settings = {'payment_ccp_rib': '', 'payment_ccp_name': '', 'payment_phone': '', 'payment_baridi': ''}
    return render_template('payment_status.html', req=req, settings=settings)

@app.route('/employer/topup', methods=['POST'])
@employer_required
def employer_topup():
    try:
        amount = int(request.form.get('amount', 0))
    except ValueError:
        amount = 0
    if amount < 100:
        flash('الحد الأدنى للشحن هو 100 دج', 'danger')
        return redirect(url_for('employer_wallet'))

    reference = f'TESHIL-{uuid.uuid4().hex[:8].upper()}'
    conn = get_db()
    conn.execute('''
        INSERT INTO payment_requests (user_id, amount, credits, reference, status)
        VALUES (%s, %s, %s, %s, 'pending')
    ''', (session['user_id'], amount, 0, reference))
    conn.commit()
    conn.close()
    return redirect(url_for('payment_status', request_id=reference))

@app.route('/my-applications')
@worker_required
def my_applications():
    conn = get_db()
    worker = conn.execute('SELECT id FROM workers WHERE user_id = %s', (session['user_id'],)).fetchone()
    apps = conn.execute('''
        SELECT a.*, j.title as job_title, j.wilaya, j.city, j.contract_type, j.salary_min, j.salary_max,
               e.company_name, u.full_name, u.phone, u.email, u.avatar_url
        FROM applications a
        JOIN jobs j ON a.job_id = j.id
        JOIN employers e ON j.employer_id = e.id
        JOIN users u ON e.user_id = u.id
        WHERE a.worker_id = %s
        ORDER BY a.created_at DESC
    ''', (worker['id'],)).fetchall()
    conn.close()
    return render_template('my_applications.html', apps=apps)

@app.route('/saved-jobs')
@worker_required
def saved_jobs():
    conn = get_db()
    worker = conn.execute('SELECT id FROM workers WHERE user_id = %s', (session['user_id'],)).fetchone()
    jobs = conn.execute('''
        SELECT j.*, e.company_name, u.full_name, u.avatar_url
        FROM saved_jobs sj
        JOIN jobs j ON sj.job_id = j.id
        JOIN employers e ON j.employer_id = e.id
        JOIN users u ON e.user_id = u.id
        WHERE sj.worker_id = %s AND j.status = 'approved'
        ORDER BY sj.created_at DESC
    ''', (worker['id'],)).fetchall()
    conn.close()
    return render_template('saved_jobs.html', jobs=jobs)

@app.route('/workers')
def workers():
    conn = get_db()
    workers = conn.execute('''
        SELECT u.full_name, u.email, u.phone, u.created_at, u.avatar_url,
               w.skills, w.experience_years, w.experience_level, w.education,
               w.city, w.wilaya, w.about, w.availability, w.expected_salary
        FROM workers w JOIN users u ON w.user_id = u.id
        WHERE w.is_public = 1
        ORDER BY w.experience_years DESC
    ''').fetchall()
    conn.close()
    return render_template('workers.html', workers=workers)

@app.route('/notifications')
@login_required
def notifications():
    conn = get_db()
    notifs = conn.execute('''
        SELECT * FROM notifications WHERE user_id = %s
        ORDER BY created_at DESC LIMIT 50
    ''', (session['user_id'],)).fetchall()
    conn.execute('UPDATE notifications SET is_read = 1 WHERE user_id = %s', (session['user_id'],))
    conn.commit()
    conn.close()
    return render_template('notifications.html', notifications=notifs)

@app.route('/contact', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def contact():
    if request.method == 'POST':
        conn = get_db()
        conn.execute('INSERT INTO contact_messages (name, email, subject, message) VALUES (%s, %s, %s, %s)',
                    (request.form['name'], request.form['email'], request.form.get('subject', ''),
                     request.form['message']))
        conn.commit()
        conn.close()
        flash('تم إرسال رسالتك بنجاح. سنتواصل معك قريباً.', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

# === ADMIN ROUTES ===

@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db()
    stats = get_stats()

    recent_users = conn.execute('''
        SELECT * FROM users ORDER BY created_at DESC LIMIT 10
    ''').fetchall()

    recent_jobs = conn.execute('''
        SELECT j.*, e.company_name, u.full_name
        FROM jobs j JOIN employers e ON j.employer_id = e.id
        JOIN users u ON e.user_id = u.id
        ORDER BY j.created_at DESC LIMIT 10
    ''').fetchall()

    jobs_by_wilaya = conn.execute('''
        SELECT wilaya, COUNT(*) as count FROM jobs
        WHERE status = 'approved' GROUP BY wilaya ORDER BY count DESC LIMIT 10
    ''').fetchall()

    jobs_by_category = conn.execute('''
        SELECT category, COUNT(*) as count FROM jobs
        WHERE status = 'approved' GROUP BY category ORDER BY count DESC LIMIT 10
    ''').fetchall()

    is_pg = bool(os.environ.get('DATABASE_URL', ''))
    month_expr = "TO_CHAR(created_at, 'YYYY-MM')" if is_pg else "strftime('%Y-%m', created_at)"
    monthly_jobs = conn.execute(f'''
        SELECT {month_expr} as month, COUNT(*) as count
        FROM jobs GROUP BY month ORDER BY month DESC LIMIT 12
    ''').fetchall()

    conn.close()
    return render_template('admin/dashboard.html', stats=stats, recent_users=recent_users,
                         recent_jobs=recent_jobs, jobs_by_wilaya=jobs_by_wilaya,
                         jobs_by_category=jobs_by_category, monthly_jobs=monthly_jobs)

@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db()
    user_type = request.args.get('type', '')
    status = request.args.get('status', 'active')
    clauses = []
    params = []
    if user_type:
        clauses.append('user_type = %s')
        params.append(user_type)
    if status == 'inactive':
        clauses.append('is_active = 0')
    else:
        clauses.append('(is_active IS NULL OR is_active = 1)')
    query = 'SELECT * FROM users'
    if clauses:
        query += ' WHERE ' + ' AND '.join(clauses)
    query += ' ORDER BY created_at DESC'

    users = conn.execute(query, params).fetchall()
    conn.close()
    return render_template('admin/users.html', users=users, user_type=user_type, status=status)

@app.route('/admin/users/<int:user_id>/toggle-verify', methods=['POST'])
@admin_required
def admin_toggle_verify(user_id):
    conn = get_db()
    user = conn.execute('SELECT is_verified FROM users WHERE id = %s', (user_id,)).fetchone()
    if user:
        new = 0 if user['is_verified'] else 1
        conn.execute('UPDATE users SET is_verified = %s WHERE id = %s', (new, user_id))
        conn.commit()
        notify(user_id, 'تم تحديث حسابك', 'تم توثيق حسابك بنجاح!' if new else 'تم إلغاء توثيق حسابك', 'info')
    conn.close()
    return redirect(url_for('admin_users', status=request.args.get('status', 'active')))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('لا يمكنك حذف حسابك', 'danger')
        return redirect(url_for('admin_users'))
    conn = get_db()
    target = conn.execute('SELECT user_type FROM users WHERE id = %s', (user_id,)).fetchone()
    if target and target['user_type'] == 'admin':
        conn.close()
        flash('لا يمكنك حذف حساب مشرف', 'danger')
        return redirect(url_for('admin_users'))
    conn.execute('DELETE FROM notifications WHERE user_id = %s', (user_id,))
    conn.execute('UPDATE users SET is_active = 0 WHERE id = %s', (user_id,))
    conn.commit()
    conn.close()
    flash('تم حذف المستخدم', 'success')
    return redirect(url_for('admin_users', status=request.args.get('status', 'active')))

@app.route('/admin/users/<int:user_id>/restore', methods=['POST'])
@admin_required
def admin_restore_user(user_id):
    conn = get_db()
    conn.execute('UPDATE users SET is_active = 1 WHERE id = %s', (user_id,))
    conn.commit()
    conn.close()
    flash('تمت استعادة المستخدم', 'success')
    return redirect(url_for('admin_users', status=request.args.get('status', 'active')))

@app.route('/admin/jobs')
@admin_required
def admin_jobs():
    conn = get_db()
    status = request.args.get('status', 'pending')
    jobs = conn.execute('''
        SELECT j.*, e.company_name, u.full_name, u.email
        FROM jobs j JOIN employers e ON j.employer_id = e.id
        JOIN users u ON e.user_id = u.id
        WHERE j.status = %s
        ORDER BY j.created_at DESC
    ''', (status,)).fetchall()
    conn.close()
    return render_template('admin/jobs.html', jobs=jobs, current_status=status)

@app.route('/admin/jobs/<int:job_id>/<action>', methods=['POST'])
@admin_required
def admin_handle_job(job_id, action):
    if action not in ('approve', 'reject', 'feature'):
        return redirect(url_for('admin_jobs'))

    conn = get_db()
    approved_job_title = None
    approved_job_wilaya = None
    if action == 'feature':
        job = conn.execute('SELECT is_featured FROM jobs WHERE id = %s', (job_id,)).fetchone()
        if job:
            conn.execute('UPDATE jobs SET is_featured = %s WHERE id = %s', (0 if job['is_featured'] else 1, job_id))
    elif action == 'approve':
        conn.execute("UPDATE jobs SET status = 'approved' WHERE id = %s", (job_id,))
        job = conn.execute('SELECT employer_id, title, wilaya, category FROM jobs WHERE id = %s', (job_id,)).fetchone()
        employer_user = conn.execute('SELECT user_id FROM employers WHERE id = %s', (job['employer_id'],)).fetchone()
        notify(employer_user['user_id'], 'تم الموافقة على وظيفتك',
               f'تمت الموافقة على نشر وظيفة "{job["title"]}" وهي الآن متاحة للباحثين عن عمل.', 'success', '/my-jobs')
        approved_job_title = job['title']
        approved_job_wilaya = job['wilaya']
    elif action == 'reject':
        job = conn.execute('SELECT j.*, u.wallet_balance FROM jobs j JOIN employers e ON j.employer_id = e.id JOIN users u ON e.user_id = u.id WHERE j.id = %s', (job_id,)).fetchone()
        if job:
            price_row = conn.execute('SELECT value FROM settings WHERE key = %s', ('job_price',)).fetchone()
            job_price = int(price_row['value']) if price_row else JOB_PRICE
            new_balance = job['wallet_balance'] + job_price
            conn.execute('UPDATE users SET wallet_balance = %s WHERE id = %s', (new_balance, job['employer_id']))
            conn.execute('''
                INSERT INTO transactions (user_id, type, amount, balance_before, balance_after, description, reference_type, reference_id, status)
                VALUES (%s, 'credit', %s, %s, %s, %s, 'refund', %s, 'completed')
            ''', (job['employer_id'], job_price, job['wallet_balance'], new_balance, f'استرداد رصيد وظيفة: {job["title"]}', job_id))
            notify(job['employer_id'], 'تم استرداد رصيد الوظيفة',
                   f'تم استرداد {job_price} دج لوظيفة "{job["title"]}" التي لم تتم الموافقة عليها.', 'success', '/employer/wallet')
        conn.execute("UPDATE jobs SET status = 'rejected' WHERE id = %s", (job_id,))

    conn.commit()
    conn.close()
    if approved_job_title:
        url = url_for('job_detail', job_id=job_id)
        loc = f'في {approved_job_wilaya}' if approved_job_wilaya else ''
        notify_all_subscribers('وظيفة جديدة!', f'{approved_job_title} {loc} — تقدم الآن على تسهيل', url)
    flash('تم تحديث حالة الوظيفة', 'success')
    return redirect(url_for('admin_jobs'))

@app.route('/admin/applications')
@admin_required
def admin_applications():
    conn = get_db()
    apps = conn.execute('''
        SELECT a.*, j.title as job_title, j.wilaya,
               u1.full_name as worker_name, u2.full_name as employer_name,
               e.company_name
        FROM applications a
        JOIN jobs j ON a.job_id = j.id
        JOIN workers w ON a.worker_id = w.id
        JOIN users u1 ON w.user_id = u1.id
        JOIN employers e ON j.employer_id = e.id
        JOIN users u2 ON e.user_id = u2.id
        ORDER BY a.created_at DESC LIMIT 50
    ''').fetchall()
    conn.close()
    return render_template('admin/applications.html', apps=apps)

@app.route('/admin/requests')
@admin_required
def admin_requests():
    conn = get_db()
    type_filter = request.args.get('type', '')
    status_filter = request.args.get('status', '')

    query = '''
        SELECT r.*, w.experience_level, w.skills,
               u1.full_name as worker_name, u1.phone, u1.email,
               e.company_name, u2.full_name as employer_name,
               j.title as job_title
        FROM requests r
        JOIN workers w ON r.worker_id = w.id
        JOIN users u1 ON w.user_id = u1.id
        LEFT JOIN employers e ON r.employer_id = e.id
        LEFT JOIN users u2 ON e.user_id = u2.id
        LEFT JOIN jobs j ON r.job_id = j.id
        WHERE 1=1
    '''
    params = []
    if type_filter:
        query += " AND r.type = %s"
        params.append(type_filter)
    if status_filter:
        query += " AND r.status = %s"
        params.append(status_filter)
    query += " ORDER BY r.created_at DESC LIMIT 100"

    reqs = conn.execute(query, params).fetchall()
    conn.close()
    return render_template('admin/requests.html', reqs=reqs, type_filter=type_filter, status_filter=status_filter)

@app.route('/admin/requests/<int:req_id>/reply', methods=['POST'])
@admin_required
def admin_reply_request(req_id):
    reply = (request.form.get('admin_reply') or '').strip()
    conn = get_db()
    req = conn.execute('SELECT * FROM requests WHERE id = %s', (req_id,)).fetchone()
    if req and reply:
        conn.execute("UPDATE requests SET admin_reply = %s, status = 'answered', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                     (reply, req_id))
        worker = conn.execute('SELECT user_id FROM workers WHERE id = %s', (req['worker_id'],)).fetchone()
        notify(worker['user_id'], 'رد من الإدارة', reply[:100], 'info', '/my-requests', conn=conn)
    conn.commit()
    conn.close()
    flash('تم إرسال الرد', 'success')
    return redirect(url_for('admin_requests'))

@app.route('/admin/requests/<int:req_id>/status/<action>', methods=['POST'])
@admin_required
def admin_request_status(req_id, action):
    if action not in ('accepted', 'rejected', 'completed', 'pending'):
        return redirect(url_for('admin_requests'))
    conn = get_db()
    req = conn.execute('SELECT * FROM requests WHERE id = %s', (req_id,)).fetchone()
    if req:
        conn.execute('UPDATE requests SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s', (action, req_id))
        worker = conn.execute('SELECT user_id FROM workers WHERE id = %s', (req['worker_id'],)).fetchone()
        notify(worker['user_id'], 'تحديث حالة الطلب', f'تم تغيير حالة طلبك إلى: {action}', 'info', '/my-requests', conn=conn)
    conn.commit()
    conn.close()
    flash('تم تحديث الحالة', 'success')
    return redirect(url_for('admin_requests'))

@app.route('/admin/backup')
@admin_required
def admin_backup():
    if os.environ.get('DATABASE_URL'):
        path = write_data_backup()
        if not path:
            flash('حدث خطأ أثناء إنشاء النسخة الاحتياطية', 'danger')
            return redirect(url_for('admin_dashboard'))
        return send_file(path, as_attachment=True, download_name=os.path.basename(path), mimetype='application/json')
    import tempfile
    src = sqlite3.connect(DB_PATH)
    fd, tmp = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    dst = sqlite3.connect(tmp)
    src.backup(dst)
    dst.close()
    src.close()
    fname = f"ta9eef-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
    return send_file(tmp, as_attachment=True, download_name=fname, mimetype='application/octet-stream')

@app.route('/admin/messages')
@admin_required
def admin_messages():
    conn = get_db()
    conn.execute('UPDATE contact_messages SET is_read = 1')
    conn.commit()
    messages = conn.execute('SELECT * FROM contact_messages ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('admin/messages.html', messages=messages)

@app.route('/admin/transactions')
@admin_required
def admin_transactions():
    conn = get_db()
    tab = request.args.get('tab', 'transactions')
    data = {'tab': tab}
    if tab == 'payment_requests':
        data['payment_requests'] = conn.execute('''
            SELECT pr.*, u.full_name, u.email, p.name as package_name
            FROM payment_requests pr
            JOIN users u ON pr.user_id = u.id
            LEFT JOIN packages p ON pr.package_id = p.id
            ORDER BY pr.created_at DESC LIMIT 100
        ''').fetchall()
    else:
        status_filter = request.args.get('status', '')
        query = 'SELECT t.*, u.full_name, u.email, u.user_type FROM transactions t JOIN users u ON t.user_id = u.id'
        params = []
        if status_filter:
            query += ' WHERE t.status = %s'
            params.append(status_filter)
        query += ' ORDER BY t.created_at DESC LIMIT 100'
        data['transactions'] = conn.execute(query, params).fetchall()
    conn.close()
    return render_template('admin/transactions.html', **data)

@app.route('/admin/transactions/<int:tid>/<action>', methods=['POST'])
@admin_required
def admin_handle_transaction(tid, action):
    if action not in ('confirm', 'cancel'):
        return redirect(url_for('admin_transactions'))
    conn = get_db()
    txn = conn.execute('SELECT * FROM transactions WHERE id = %s', (tid,)).fetchone()
    if not txn:
        flash('المعاملة غير موجودة', 'danger')
        return redirect(url_for('admin_transactions'))

    if action == 'confirm':
        conn.execute('''
            UPDATE users SET wallet_balance = wallet_balance + %s WHERE id = %s
        ''', (txn['amount'], txn['user_id']))
        conn.execute("UPDATE transactions SET status = 'completed' WHERE id = %s", (tid,))
        notify(txn['user_id'], 'تم تأكيد المعاملة',
               f'تم إضافة {txn["amount"]} رصيد إلى محفظتك.', 'success', '/employer/wallet')
        flash(f'تم تأكيد المعاملة #{tid} وإضافة الرصيد', 'success')
    else:
        conn.execute("UPDATE transactions SET status = 'cancelled' WHERE id = %s", (tid,))
        notify(txn['user_id'], 'تم إلغاء المعاملة',
               f'تم إلغاء معاملة شحن الرصيد بقيمة {txn["amount"]}.', 'danger', '/employer/wallet')
        flash(f'تم إلغاء المعاملة #{tid}', 'info')

    conn.commit()
    conn.close()
    return redirect(url_for('admin_transactions'))

@app.route('/admin/payment-requests/<int:rid>/<action>', methods=['POST'])
@admin_required
def admin_handle_payment(rid, action):
    if action not in ('confirm', 'cancel'):
        return redirect(url_for('admin_transactions', tab='payment_requests'))
    conn = get_db()
    req = conn.execute('SELECT * FROM payment_requests WHERE id = %s', (rid,)).fetchone()
    if not req:
        flash('طلب الدفع غير موجود', 'danger')
        return redirect(url_for('admin_transactions', tab='payment_requests'))

    if action == 'confirm':
        conn.execute('UPDATE users SET wallet_balance = COALESCE(wallet_balance, 0) + %s WHERE id = %s', (req['amount'], req['user_id']))
        user = conn.execute('SELECT wallet_balance FROM users WHERE id = %s', (req['user_id'],)).fetchone()
        balance_before = user['wallet_balance'] - req['amount']
        balance_after = user['wallet_balance']
        conn.execute('''
            INSERT INTO transactions (user_id, type, amount, balance_before, balance_after, description, reference_type, reference_id, status)
            VALUES (%s, 'credit', %s, %s, %s, %s, 'payment_request', %s, 'completed')
        ''', (req['user_id'], req['amount'], balance_before, balance_after, f'تأكيد طلب دفع: {req["reference"]}', req['id']))
        conn.execute("UPDATE payment_requests SET status = 'confirmed', updated_at = CURRENT_TIMESTAMP WHERE id = %s", (rid,))
        notify(req['user_id'], 'تم تأكيد طلب الدفع',
               f'تم تأكيد طلب الدفع {req["reference"]} وإضافة {req["amount"]} دج إلى محفظتك.', 'success', '/employer/wallet', conn=conn)
        flash(f'تم تأكيد طلب الدفع {req["reference"]}', 'success')
    else:
        conn.execute("UPDATE payment_requests SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP WHERE id = %s", (rid,))
        notify(req['user_id'], 'تم إلغاء طلب الدفع',
               f'تم إلغاء طلب الدفع {req["reference"]}.', 'danger', '/employer/wallet', conn=conn)
        flash(f'تم إلغاء طلب الدفع {req["reference"]}', 'info')

    conn.commit()
    conn.close()
    return redirect(url_for('admin_transactions', tab='payment_requests'))

@app.route('/admin/wallet/<int:user_id>/adjust', methods=['POST'])
@admin_required
def admin_adjust_wallet(user_id):
    try:
        amount = int(request.form.get('amount', 0))
    except ValueError:
        amount = 0
    if amount == 0:
        flash('الرجاء إدخال مبلغ صحيح', 'danger')
        return redirect(url_for('admin_users'))

    conn = get_db()
    user = conn.execute('SELECT COALESCE(wallet_balance,0) as wallet_balance FROM users WHERE id = %s', (user_id,)).fetchone()
    if not user:
        flash('المستخدم غير موجود', 'danger')
        return redirect(url_for('admin_users'))

    new_balance = user['wallet_balance'] + amount
    txn_type = 'credit' if amount > 0 else 'debit'
    conn.execute('UPDATE users SET wallet_balance = %s WHERE id = %s', (new_balance, user_id))
    conn.execute('''
        INSERT INTO transactions (user_id, type, amount, balance_before, balance_after, description, reference_type, status)
        VALUES (%s, %s, %s, %s, %s, %s, 'admin_adjust', 'completed')
    ''', (user_id, txn_type, abs(amount), user['wallet_balance'], new_balance,
          f'تعديل يدوي من الإدارة: {"+" + str(amount) if amount > 0 else str(amount)}'))
    notify(user_id, 'تعديل الرصيد',
           f'تم تعديل رصيد محفظتك بمقدار {amount} دج.', 'info', '/employer/wallet')

    conn.commit()
    conn.close()
    flash(f'تم تعديل رصيد المستخدم بمقدار {amount}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    conn = get_db()
    if request.method == 'POST':
        job_price = request.form.get('job_price', type=int)
        if job_price and job_price > 0:
            conn.execute("INSERT INTO settings (key, value) VALUES (%s, %s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value" if os.environ.get('DATABASE_URL') else 'INSERT OR REPLACE INTO settings (key, value) VALUES (%s, %s)', ('job_price', str(job_price)))
        for key in ['site_name', 'site_description', 'contact_email', 'payment_ccp_rib', 'payment_ccp_name', 'payment_phone', 'payment_baridi']:
            val = request.form.get(key, '').strip()
            if val:
                conn.execute("INSERT INTO settings (key, value) VALUES (%s, %s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value" if os.environ.get('DATABASE_URL') else 'INSERT OR REPLACE INTO settings (key, value) VALUES (%s, %s)', (key, val))
        conn.commit()
        conn.close()
        flash('تم حفظ الإعدادات بنجاح', 'success')
        return redirect(url_for('admin_settings'))

    settings = {row['key']: row['value'] for row in conn.execute('SELECT * FROM settings').fetchall()}
    packages = conn.execute('SELECT * FROM packages ORDER BY price ASC').fetchall()
    conn.close()
    return render_template('admin/settings.html', settings=settings, packages=packages)

@app.route('/admin/packages/add', methods=['POST'])
@admin_required
def admin_add_package():
    conn = get_db()
    conn.execute('INSERT INTO packages (name, credits, price, duration_days) VALUES (%s, %s, %s, %s)', (
        request.form['name'], int(request.form['credits']),
        int(request.form['price']), int(request.form.get('duration_days', 365))
    ))
    conn.commit()
    conn.close()
    flash('تم إضافة الباقة', 'success')
    return redirect(url_for('admin_settings'))

@app.route('/admin/packages/<int:pid>/toggle', methods=['POST'])
@admin_required
def admin_toggle_package(pid):
    conn = get_db()
    pkg = conn.execute('SELECT is_active FROM packages WHERE id = %s', (pid,)).fetchone()
    if pkg:
        conn.execute('UPDATE packages SET is_active = %s WHERE id = %s', (0 if pkg['is_active'] else 1, pid))
    conn.commit()
    conn.close()
    return redirect(url_for('admin_settings'))

@app.route('/admin/banners')
@admin_required
def admin_banners():
    conn = get_db()
    banners = conn.execute('SELECT * FROM banners ORDER BY sort_order ASC, id DESC').fetchall()
    conn.close()
    return render_template('admin/banners.html', banners=banners)

@app.route('/admin/banners/add', methods=['POST'])
@admin_required
def admin_add_banner():
    title = request.form.get('title', '').strip()
    link_url = request.form.get('link_url', '').strip()
    position = request.form.get('position', 'home_top')
    if position not in ('home_top', 'home_bottom'):
        position = 'home_top'
    try:
        sort_order = int(request.form.get('sort_order', 0))
    except ValueError:
        sort_order = 0

    if not title:
        flash('يرجى إدخال عنوان البانر', 'danger')
        return redirect(url_for('admin_banners'))

    image_url = ''
    if 'image' in request.files and request.files['image'].filename:
        file = request.files['image']
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if ext not in ALLOWED_EXTENSIONS:
            flash('الصيغة غير مدعومة. يرجى اختيار PNG, JPG, GIF أو WebP', 'danger')
            return redirect(url_for('admin_banners'))
        if not validate_image(file):
            flash('الملف ليس صورة صالحة', 'danger')
            return redirect(url_for('admin_banners'))
        file.seek(0, os.SEEK_END)
        if file.tell() > AVATAR_MAX_SIZE:
            flash('حجم الصورة كبير جداً. الحد الأقصى 2 ميغابايت', 'danger')
            return redirect(url_for('admin_banners'))
        file.seek(0)
        upload_dir = os.path.join(STORAGE_ROOT, 'uploads', 'banners')
        os.makedirs(upload_dir, exist_ok=True)
        filename = f'banner_{int(time.time())}_{uuid.uuid4().hex[:6]}.{ext}'
        file.save(os.path.join(upload_dir, filename))
        image_url = url_for('static', filename=f'uploads/banners/{filename}')
    else:
        image_url = request.form.get('image_url', '').strip()

    if not image_url:
        flash('يرجى رفع صورة البانر أو إدخال رابط صورة', 'danger')
        return redirect(url_for('admin_banners'))

    conn = get_db()
    conn.execute('''
        INSERT INTO banners (title, image_url, link_url, position, is_active, sort_order)
        VALUES (%s, %s, %s, %s, %s, %s)
    ''', (title, image_url, link_url, position, 1, sort_order))
    conn.commit()
    conn.close()
    flash('تم إضافة البانر بنجاح', 'success')
    return redirect(url_for('admin_banners'))

@app.route('/admin/banners/<int:bid>/toggle', methods=['POST'])
@admin_required
def admin_toggle_banner(bid):
    conn = get_db()
    b = conn.execute('SELECT is_active FROM banners WHERE id = %s', (bid,)).fetchone()
    if b:
        conn.execute('UPDATE banners SET is_active = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s', (0 if b['is_active'] else 1, bid))
        conn.commit()
    conn.close()
    return redirect(url_for('admin_banners'))

@app.route('/admin/banners/<int:bid>/delete', methods=['POST'])
@admin_required
def admin_delete_banner(bid):
    conn = get_db()
    b = conn.execute('SELECT image_url FROM banners WHERE id = %s', (bid,)).fetchone()
    if b:
        conn.execute('DELETE FROM banners WHERE id = %s', (bid,))
        conn.commit()
        conn.close()
        if b['image_url'] and b['image_url'].startswith('/static/uploads/banners/'):
            path = os.path.join(STORAGE_ROOT, b['image_url'].replace('/static/', '', 1))
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass
        flash('تم حذف البانر', 'info')
        return redirect(url_for('admin_banners'))
    conn.close()
    flash('البانر غير موجود', 'warning')
    return redirect(url_for('admin_banners'))

@app.route('/banner/<int:bid>/click')
def banner_click(bid):
    conn = get_db()
    b = conn.execute('SELECT link_url FROM banners WHERE id = %s AND is_active = 1 AND (ends_at IS NULL OR ends_at > CURRENT_TIMESTAMP)', (bid,)).fetchone()
    if b:
        conn.execute('UPDATE banners SET clicks = clicks + 1 WHERE id = %s', (bid,))
        conn.execute('INSERT INTO banner_clicks (banner_id, referrer) VALUES (%s, %s)', (bid, (request.referrer or '')[:500]))
        conn.commit()
        conn.close()
        target = b['link_url'] or url_for('index')
        return redirect(target)
    conn.close()
    return redirect(url_for('index'))

def get_ad_price():
    conn = get_db()
    row = conn.execute('SELECT value FROM settings WHERE key = %s', ('ad_price_per_week',)).fetchone()
    conn.close()
    try:
        return int(row['value']) if row else AD_PRICE_PER_WEEK
    except (TypeError, ValueError):
        return AD_PRICE_PER_WEEK

@app.route('/advertise')
def advertise():
    price_per_week = get_ad_price()
    durations = [7, 14, 30]
    plans = [{'days': d, 'price': round(d / 7 * price_per_week)} for d in durations]
    return render_template('advertise.html', price_per_week=price_per_week, plans=plans)

@app.route('/advertise/order', methods=['POST'])
@login_required
def ad_create_order():
    title = request.form.get('title', '').strip()
    link_url = request.form.get('link_url', '').strip()
    position = request.form.get('position', 'home_top')
    if position not in ('home_top', 'home_bottom'):
        position = 'home_top'
    try:
        duration_days = int(request.form.get('duration_days', 7))
    except ValueError:
        duration_days = 7
    if duration_days not in (7, 14, 30):
        duration_days = 7

    if not title:
        flash('يرجى إدخال عنوان الإعلان', 'danger')
        return redirect(url_for('advertise'))

    image_url = ''
    if 'image' in request.files and request.files['image'].filename:
        file = request.files['image']
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        if ext not in ALLOWED_EXTENSIONS:
            flash('الصيغة غير مدعومة. يرجى اختيار PNG, JPG, GIF أو WebP', 'danger')
            return redirect(url_for('advertise'))
        if not validate_image(file):
            flash('الملف ليس صورة صالحة', 'danger')
            return redirect(url_for('advertise'))
        file.seek(0, os.SEEK_END)
        if file.tell() > AVATAR_MAX_SIZE:
            flash('حجم الصورة كبير جداً. الحد الأقصى 2 ميغابايت', 'danger')
            return redirect(url_for('advertise'))
        file.seek(0)
        upload_dir = os.path.join(STORAGE_ROOT, 'uploads', 'ads')
        os.makedirs(upload_dir, exist_ok=True)
        filename = f'ad_{int(time.time())}_{uuid.uuid4().hex[:6]}.{ext}'
        file.save(os.path.join(upload_dir, filename))
        image_url = url_for('static', filename=f'uploads/ads/{filename}')
    else:
        image_url = request.form.get('image_url', '').strip()

    if not image_url:
        flash('يرجى رفع صورة الإعلان أو إدخال رابط صورة', 'danger')
        return redirect(url_for('advertise'))

    price = round(duration_days / 7 * get_ad_price())
    conn = get_db()
    if os.environ.get('DATABASE_URL'):
        cur = conn.execute('''
            INSERT INTO ad_orders (user_id, title, image_url, link_url, position, duration_days, price)
            VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id
        ''', (session['user_id'], title, image_url, link_url, position, duration_days, price))
        oid = cur.fetchone()['id']
    else:
        cur = conn.execute('''
            INSERT INTO ad_orders (user_id, title, image_url, link_url, position, duration_days, price)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], title, image_url, link_url, position, duration_days, price))
        oid = cur.lastrowid
    conn.commit()
    conn.close()
    flash('تم إنشاء طلب الإعلان. أكمل الدفع لإطلاقه.', 'success')
    return redirect(url_for('ad_order_status', oid=oid))

@app.route('/advertise/order/<int:oid>')
@login_required
def ad_order_status(oid):
    refresh_ad_order_statuses()
    conn = get_db()
    order = conn.execute('SELECT * FROM ad_orders WHERE id = %s AND user_id = %s', (oid, session['user_id'])).fetchone()
    settings = {row['key']: row['value'] for row in conn.execute("SELECT * FROM settings WHERE key IN ('payment_ccp_rib','payment_ccp_name','payment_phone','payment_baridi')").fetchall()}
    conn.close()
    if not order:
        flash('طلب الإعلان غير موجود', 'danger')
        return redirect(url_for('advertise'))
    return render_template('ad_order_status.html', order=order, settings=settings)

@app.route('/advertise/order/<int:oid>/receipt', methods=['POST'])
@login_required
def ad_upload_receipt(oid):
    conn = get_db()
    order = conn.execute('SELECT * FROM ad_orders WHERE id = %s AND user_id = %s', (oid, session['user_id'])).fetchone()
    if not order:
        conn.close()
        flash('طلب الإعلان غير موجود', 'danger')
        return redirect(url_for('advertise'))
    if order['status'] != 'pending_payment':
        conn.close()
        flash('لا يمكن رفع إيصال لهذا الطلب الآن', 'warning')
        return redirect(url_for('ad_order_status', oid=oid))
    if 'receipt' not in request.files:
        conn.close()
        flash('الرجاء اختيار ملف الإيصال', 'danger')
        return redirect(url_for('ad_order_status', oid=oid))
    file = request.files['receipt']
    if file.filename == '':
        conn.close()
        flash('الرجاء اختيار ملف الإيصال', 'danger')
        return redirect(url_for('ad_order_status', oid=oid))
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    if ext not in ALLOWED_RECEIPT_EXTENSIONS:
        conn.close()
        flash('صيغة الملف غير مدعومة. يرجى اختيار PNG, JPG, PDF أو WebP', 'danger')
        return redirect(url_for('ad_order_status', oid=oid))
    if ext != 'pdf' and not validate_image(file):
        conn.close()
        flash('الملف ليس صورة صالحة', 'danger')
        return redirect(url_for('ad_order_status', oid=oid))
    file.seek(0, os.SEEK_END)
    if file.tell() > RECEIPT_MAX_SIZE:
        conn.close()
        flash('حجم الملف كبير جداً. الحد الأقصى 5 ميغابايت', 'danger')
        return redirect(url_for('ad_order_status', oid=oid))
    file.seek(0)
    filename = f'ad_receipt_{oid}_{uuid.uuid4().hex[:8]}.{ext}'
    receipt_dir = os.path.join(STORAGE_ROOT, 'receipts')
    os.makedirs(receipt_dir, exist_ok=True)
    file.save(os.path.join(receipt_dir, filename))
    conn.execute("UPDATE ad_orders SET receipt_path = %s, status = 'paid', updated_at = CURRENT_TIMESTAMP WHERE id = %s", (filename, oid))
    conn.commit()
    conn.close()
    flash('تم رفع الإيصال بنجاح. سنقوم بمراجعته قريباً.', 'success')
    return redirect(url_for('ad_order_status', oid=oid))

@app.route('/my-ads')
@login_required
def my_ads():
    refresh_ad_order_statuses()
    conn = get_db()
    orders = conn.execute('SELECT * FROM ad_orders WHERE user_id = %s ORDER BY id DESC', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('my_ads.html', orders=orders)

@app.route('/admin/ads')
@admin_required
def admin_ads():
    refresh_ad_order_statuses()
    conn = get_db()
    orders = conn.execute('''
        SELECT o.*, u.full_name, u.email
        FROM ad_orders o JOIN users u ON o.user_id = u.id
        ORDER BY o.id DESC LIMIT 100
    ''').fetchall()
    banners = conn.execute('''
        SELECT b.*, (b.ends_at IS NOT NULL AND b.ends_at <= CURRENT_TIMESTAMP) as is_expired
        FROM banners b ORDER BY b.id DESC LIMIT 50
    ''').fetchall()
    revenue = conn.execute("SELECT COALESCE(SUM(price), 0) AS total FROM ad_orders WHERE status IN ('paid','active')").fetchone()
    pending = conn.execute("SELECT COUNT(*) AS c FROM ad_orders WHERE status = 'pending_payment'").fetchone()
    price_row = conn.execute("SELECT value FROM settings WHERE key = 'ad_price_per_week'").fetchone()
    recent_clicks = conn.execute('''
        SELECT bc.id, bc.referrer, bc.clicked_at, b.title AS banner_title
        FROM banner_clicks bc JOIN banners b ON bc.banner_id = b.id
        ORDER BY bc.id DESC LIMIT 30
    ''').fetchall()
    conn.close()
    return render_template('admin/ads.html', orders=orders, banners=banners,
                           revenue=revenue['total'] if revenue else 0,
                           pending_count=pending['c'] if pending else 0,
                           ad_price=price_row['value'] if price_row else AD_PRICE_PER_WEEK,
                           recent_clicks=recent_clicks)

@app.route('/admin/ads/<int:oid>/confirm', methods=['POST'])
@admin_required
def admin_confirm_ad(oid):
    conn = get_db()
    order = conn.execute('SELECT * FROM ad_orders WHERE id = %s', (oid,)).fetchone()
    if not order:
        conn.close()
        flash('طلب الإعلان غير موجود', 'danger')
        return redirect(url_for('admin_ads'))
    if order['status'] not in ('pending_payment', 'paid'):
        conn.close()
        flash('لا يمكن تأكيد هذا الطلب', 'warning')
        return redirect(url_for('admin_ads'))

    now = datetime.now()
    ends_at = now + timedelta(days=order['duration_days'])
    conn.execute('''
        INSERT INTO banners (title, image_url, link_url, position, is_active, sort_order, ends_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    ''', (order['title'], order['image_url'], order['link_url'], order['position'], 1, 0, ends_at.strftime('%Y-%m-%d %H:%M:%S')))
    conn.execute('''
        UPDATE ad_orders SET status = 'active', starts_at = CURRENT_TIMESTAMP, ends_at = %s,
            updated_at = CURRENT_TIMESTAMP, banner_id = (SELECT MAX(id) FROM banners)
        WHERE id = %s
    ''', (ends_at.strftime('%Y-%m-%d %H:%M:%S'), oid))
    conn.commit()
    notify(order['user_id'], 'تم تفعيل إعلانك', f'تم تأكيد دفع إعلان "{order["title"]}" وتفعيله لمدة {order["duration_days"]} يوماً.', 'success', '/my-ads', conn=conn)
    conn.commit()
    conn.close()
    flash(f'تم تأكيد الدفع وتفعيل الإعلان "{order["title"]}"', 'success')
    return redirect(url_for('admin_ads'))

@app.route('/admin/ads/<int:oid>/reject', methods=['POST'])
@admin_required
def admin_reject_ad(oid):
    conn = get_db()
    order = conn.execute('SELECT * FROM ad_orders WHERE id = %s', (oid,)).fetchone()
    if order and order['status'] in ('pending_payment', 'paid'):
        conn.execute("UPDATE ad_orders SET status = 'rejected', updated_at = CURRENT_TIMESTAMP WHERE id = %s", (oid,))
        conn.commit()
        notify(order['user_id'], 'تم رفض الإعلان', f'نأسف، تم رفض إعلان "{order["title"]}". راجع بياناتك.', 'danger', '/my-ads', conn=conn)
        conn.commit()
    conn.close()
    flash('تم رفض الطلب', 'info')
    return redirect(url_for('admin_ads'))

@app.route('/admin/ads/settings', methods=['POST'])
@admin_required
def admin_ads_settings():
    try:
        price = int(request.form.get('ad_price_per_week', 0))
    except ValueError:
        price = 0
    if price < 0:
        price = 0
    conn = get_db()
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (%s, %s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value" if os.environ.get('DATABASE_URL') else 'INSERT OR REPLACE INTO settings (key, value) VALUES (%s, %s)',
        ('ad_price_per_week', str(price))
    )
    conn.commit()
    conn.close()
    flash('تم تحديث سعر الإعلان', 'success')
    return redirect(url_for('admin_ads'))

@app.route('/robots.txt')
def robots_txt():
    base = request.url_root.rstrip('/')
    return f'''User-agent: *
Allow: /
Disallow: /admin/
Disallow: /login/
Disallow: /register/
Disallow: /forgot-password/
Disallow: /reset-password/
Disallow: /employer/wallet/
Disallow: /profile/
Disallow: /my-jobs/
Disallow: /my-applications/
Disallow: /saved-jobs/
Disallow: /notifications/
Sitemap: {base}/sitemap.xml
''', 200, {'Content-Type': 'text/plain'}

@app.route('/sitemap.xml')
def sitemap_xml():
    base = request.url_root.rstrip('/')
    today = datetime.utcnow().strftime('%Y-%m-%d')
    urls = [
        ('/', 'daily', '1.0'),
        ('/about', 'monthly', '0.8'),
        ('/faq', 'monthly', '0.7'),
        ('/contact', 'monthly', '0.6'),
        ('/terms', 'monthly', '0.5'),
        ('/privacy', 'monthly', '0.5'),
        ('/jobs', 'weekly', '0.9'),
        ('/workers', 'weekly', '0.7'),
    ]
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    for path, freq, priority in urls:
        xml += f'''  <url>
    <loc>{base}{path}</loc>
    <lastmod>{today}</lastmod>
    <changefreq>{freq}</changefreq>
    <priority>{priority}</priority>
  </url>\n'''
    conn = get_db()
    jobs = conn.execute('SELECT id, updated_at FROM jobs WHERE status = %s ORDER BY id', ('approved',)).fetchall()
    conn.close()
    for job in jobs:
        updated = date_filter(job['updated_at']) if job['updated_at'] else today
        xml += f'''  <url>
    <loc>{base}/jobs/{job['id']}</loc>
    <lastmod>{updated}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.9</priority>
  </url>\n'''
    for slug, name in WILAYA_SLUGS.items():
        xml += f'''  <url>
    <loc>{base}/wilaya/{slug}</loc>
    <lastmod>{today}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.7</priority>
  </url>\n'''
    xml += '</urlset>'
    return xml, 200, {'Content-Type': 'application/xml'}

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.route('/sw.js')
def serve_sw():
    return send_from_directory('static', 'sw.js', mimetype='application/javascript')

@app.route('/manifest.webmanifest')
def serve_manifest():
    return send_from_directory('static', 'manifest.webmanifest', mimetype='application/manifest+json')

@app.route('/<path:filename>')
def serve_root_files(filename):
    if filename.startswith('google') and filename.endswith('.html'):
        return send_from_directory('static', filename)
    abort(404)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
