# منصة تسهيل (Ta9eef) — توثيق تقني للمطورين

منصة جزائرية للتوظيف تربط الباحثين عن عمل (العمال) بأرباب العمل، مع نظام محفظة ومدفوعات محلية وإعلانات مموّلة ولوحة إدارة كاملة.

- **الإنتاج**: https://teeshil-algeria.onrender.com
- **البيئة**: Render (مشروع `teshil`) — خدمة `talented-respect` + PostgreSQL + وحدة تخزين دائمة
- **اللغة**: Python 3.12 + Flask

---

## 1) التقنيات المستخدمة

| المكوّن | الاختيار |
|---|---|
| لغة/إطار العمل | Python 3.12، Flask 3.1.3 |
| القوالب | Jinja2 (Bootstrap 5 عبر CDN، RTL) |
| قاعدة البيانات | SQLite (تطوير محلي) / PostgreSQL 18 (إنتاج) عبر `psycopg2` |
| خادم الإنتاج | Gunicorn 23 (`gthread`، 2 عمّال × 4 خيوط) |
| الحماية | `flask-limiter`، CSRF مدمج، جلسات آمنة، ترويسات أمان/CSP |
| الإشعارات | إشعارات داخلية + Web Push (`pywebpush`/VAPID) |
| البريد | Brevo API (الإنتاج) مع خطة احتياطية SMTP |
| OAuth (اختياري) | Google وFacebook |
| أخرى | `python-dotenv`، `requests`، PWA (`sw.js`/`manifest`) |

---

## 2) الأدوار والصلاحيات

- **worker** — باحث عن عمل: ملف شخصي، بحث عن وظائف، تقديم، حفظ وظائف، طلبات، إشعارات.
- **employer** — صاحب عمل: ملف شركة، نشر وظائف (يستنزف رصيداً)، محفظة/باقات، إدارة التقديمات والطلبات، إعلانات.
- **admin** — لوحة تحكم كاملة (مستخدمون، وظائف، طلبات، رسائل، معاملات، إعلانات، باقات، إعدادات، نسخ احتياطي).

حساب المشرف يُنشأ تلقائياً عند أول تشغيل من `ADMIN_EMAIL`/`ADMIN_PASSWORD`.

---

## 3) بنية المشروع

```
ta9eef-algeria/
├── app.py                 # التطبيق كاملاً (المسارات، النماذج، الجداول، الوظائف المساعدة)
├── Dockerfile             # صورة الإنتاج (python:3.12-slim + gunicorn)
├── requirements.txt       # الاعتماديات
├── runtime.txt            # نسخة Python للمنصات
├── AGENTS.md              # قواعد العمل المشتركة للفرق/الأدوات
├── ta9eef.db              # قاعدة SQLite المحلية (لا تُدفع إلى git)
├── .env                   # إعدادات محلية (لا تُدفع إلى git)
├── templates/             # قوالب Jinja2 (أحادية اللغة العربية، RTL)
│   ├── base.html          # الهيكل المشترك (شريط علوي، إشعارات، PWA)
│   ├── partials/          # أجزاء صفحة الدخول (auth_style/visual/script)
│   └── admin/             # لوحة التحكم (10 صفحات)
└── static/                # CSS، صور، خطوط، PWA
    ├── uploads/           # صور المستخدمين/البانرات/الإعلانات (STORAGE_ROOT محلياً)
    ├── receipts/          # إيصالات الدفع
    └── backups/           # نسخ JSON تلقائية (محلياً)
```

> في الإنتاج: ملفات `uploads/` و`receipts/` و`backups/` تُحفظ على **الوحدة التخزينية** `talented-respect-volume` المركّبة في `/app/storage` (متغير `STORAGE_ROOT=/app/storage`)، وليست داخل الـ container العابر.

---

## 4) التشغيل محلياً

```bash
cd ta9eef-algeria
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # ثم عبّئ القيم حسب الجدول في §6
python app.py          # → http://localhost:8080
```

- بدون `DATABASE_URL` يعمل التطبيق بـ SQLite (`ta9eef.db`) وينشئ الجداول تلقائياً عند الاستيراد.
- الجداول تُنشأ في `init_db()` التي تُستدعى عند استيراد `app`، وهي **جولية** (لا تمسّ البيانات).

---

## 5) النشر إلى Railway

```bash
cd /Users/dz/ta9eef-algeria
railway up --service talented-respect -y -e production -w "anisztn's Projects" --detach < /dev/null
railway deployment list --service talented-respect   # لمتابعة الحالة
```

> **ملاحظة مهمة**: أضف `< /dev/null` (إغلاق stdin) وإلا يعلق الأمر عند `Indexing...` بلا أي رسالة (يُلاحظ مع CLI 5.30.x). الدفع عبر GitHub لا يعمل بشكل موثوق.

قواعد النشر (انظر `AGENTS.md`):
1. قبل أي نشر، خذ نسخة احتياطية من بيانات الإنتاج (§7).
2. لا تنشر إذا كانت البيئة تستخدم SQLite غير دائم — إنتاجنا Postgres + وحدة تخزين فلا تُصفّر البيانات.

---

## 6) المتغيرات البيئية

| المتغير | الوصف | الافتراضي |
|---|---|---|
| `DATABASE_URL` | اتصال PostgreSQL؛ فارغ = SQLite | `''` |
| `SECRET_KEY` | مفتاح الجلسات | عشوائي عند الاستيراد |
| `BASE_URL` | رابط الموقع (يُفعّل جلسات آمنة) | `http://localhost:8080` |
| `PORT` | منفذ الخادم | `8080` |
| `STORAGE_ROOT` | جذر تخزين الملفات المرفوعة | `static/` |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | حساب المشرف الافتراضي | `admin@ta9eef.dz` / `admin123456` |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | OAuth Google (اختياري) | فارغ |
| `FACEBOOK_APP_ID` / `FACEBOOK_APP_SECRET` | OAuth Facebook (اختياري) | فارغ |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` | بريد احتياطي (Gmail) | - |
| `BREVO_API_KEY` / `BREVO_SENDER` / `BREVO_SENDER_NAME` | إرسال البريد في الإنتاج (Brevo) | - |
| `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` / `VAPID_SUBJECT` | Web Push | - |

> في الإنتاج يُرسل البريد عبر **Brevo API** فقط (Railway يحجب SMTP). أُثبت خيار "Restrict API calls to authorised IPs" معطّلاً في Brevo وإلا يُرفض بـ 401.

---

## 7) النسخ الاحتياطي والاستعادة

- **تلقائي**: خيط `_daily_loop` يكتب يومياً `STORAGE_ROOT/backups/ta9eef-data-<stamp>.json` (يحتفظ بآخر 7) عبر `write_data_backup()`.
- **يدوي**: لوحة الإدارة ← `/admin/backup` (ينزّل JSON أو ملف `.db` حسب البيئة).
- **قبل أي تعديل على بيانات الإنتاج**: احفظ نسخة في `/Users/dz/ta9eef-algeria-backups`.
- **نسخة PostgreSQL كاملة** (عبر نفق SSH + `pg_dump` — يتطلب عميل بنفس نسخة السيرفر 18):
  ```bash
  railway connect Postgres --tunnel-only -e production   # يطبع URL محلي
  pg_dump "postgresql://...@127.0.0.1:PORT/railway" -f backup.sql
  ```
  بديل متوافق مع أي إصدار: سكريبت `psycopg2` يُفرّغ كل الجداول إلى JSON بنفس منطق `write_data_backup()`.

---

## 8) نموذج قاعدة البيانات

جداول **19** في المخطط (`SCHEMA` في `app.py`):

| الجدول | الغرض |
|---|---|
| `users` | الحسابات (worker/employer/admin)، الرصيد، حالة التوثيق |
| `workers` | بيانات العامل (مهارات، خبرة، تعليم، توفر، سيرة ذاتية...) |
| `employers` | بيانات الشركة (الاسم، الوصف، القطاع، الحجم...) |
| `jobs` | الوظائف (الوصف، المتطلبات، العقد، الراتب، الحالة...) |
| `applications` | التقديمات على الوظائف |
| `saved_jobs` | الوظائف المحفوظة |
| `requests` | الطلبات بين العامل وصاحب العمل (طلب/موعد/معلومة) |
| `notifications` | الإشعارات الداخلية |
| `push_subscriptions` | اشتراكات Web Push |
| `reviews` | التقييمات (1–5) |
| `contact_messages` | رسائل "اتصل بنا" |
| `transactions` | حركات المحفظة (credit/debit مع الرصيد قبل/بعد) |
| `packages` | باقات الرصيد (اسم، اعتمادات، سعر) |
| `settings` | إعدادات أزواج key/value قابلة للتهيئة |
| `reset_tokens` | رموز استعادة كلمة المرور |
| `payment_requests` | طلبات الدفع (مرجع `TESHIL-XXXX`، إيصال، حالة) |
| `banners` | البانرات الإعلانية (الصفحة الرئيسية) |
| `banner_clicks` | عدّادات نقر البانرات |
| `ad_orders` | إعلانات المستخدمين الممولة |

إعدادات قابلة للتهيئة عبر لوحة الإدارة: `job_price` (افتراضي 1000 دج)، `ad_price_per_week` (افتراضي 5000 دج)، `site_name`، `site_description`، `contact_email`، ومعلومات الدفع (`payment_ccp_rib`، `payment_ccp_name`، `payment_phone`، `payment_baridi`).

---

## 9) خرائط المسارات الرئيسية

**الواجهة العامة**: `/`، `/jobs`، `/jobs/<id>`، `/wilaya/<slug>`، `/workers`، `/advertise`، `/contact`، `/about`، `/faq`، `/terms`، `/privacy`، `/sitemap.xml`، `/robots.txt`

**الحسابات**: `/register`، `/login`، `/logout`، `/forgot-password`، `/reset-password/<token>`، `/delete-account`، `/login/google`، `/login/facebook`

**العامل**: `/profile`، `/upload-avatar`، `/my-applications`، `/saved-jobs`، `/my-requests`، `/requests/create`، `/notifications`، `/push/*`

**صاحب العمل**: `/profile`، `/jobs/create`، `/my-jobs`، `/jobs/<id>/toggle|delete`، `/employer/requests`، `/employer/wallet`، `/employer/buy-package`، `/employer/checkout/<id>`، `/employer/payment/create`، `/employer/payment/<ref>`، `/employer/topup`، `/employer/payment/<ref>/receipt`، `/applications`، `/my-ads`، `/advertise/order`

**الإدارة** (`/admin`): `users`، `jobs`، `applications`، `requests`، `messages`، `transactions`، `wallet/<id>/adjust`، `settings`، `packages`، `banners`، `ads`، `backup`

**الخدمة**: `/health`، `/_version`، `/push/vapid-key`

---

## 10) سير الدفع

1. صاحب العمل يشتري **باقة** أو **يشحن رصيداً** (الحد الأدنى 100 دج) → يُنشأ `payment_request` بمرجع `TESHIL-XXXXXX`.
2. المستخدم يدفع عبر الطرق المعروضة (CCP/Baridi/هاتف) ويرفع **الإيصال** (`/employer/payment/<ref>/receipt`).
3. المشرف يؤكد الطلب من لوحة الإدارة (`/admin/transactions`) → يُضاف الرصيد للمحفظة وتُسجَّل معاملة `credit`.
4. نشر الوظيفة يخصم `job_price` من المحفظة (`debit` مع `reference_type='job_post'`).
5. الإعلانات: `ad_orders` تُسعَّر أسبوعياً (7/14/30 يوماً) ويؤكدها المشرف.

---

## 11) الأمان

- CSRF لجميع طلبات POST (عدا `CSRF_SAFE_ENDPOINTS`) — الرمز يُحقن تلقائياً في النماذج عبر JS في `base.html`.
- كلمات المرور عبر `werkzeug.security` (bcrypt/pbkdf2).
- `flask-limiter` على الدخول (5/دقيقة) والتسجيل (3/دقيقة) والاتصال.
- ترويسات أمان + CSP صارمة (تسمح بـ jsdelivr/Google Fonts فقط).
- فحص الصور المرفوعة بمحتواها (`validate_image`) وحدود الحجم (2MB/5MB).
- `ProxyFix` للعمل خلف وكيل Railway.
- **ملاحظة**: `X-Frame-Options: DENY` وCSP قد تحجب المحتوى الخارجي — عند إضافة مصادر جديدة حدّث الترويسة في `add_security_headers`.

---

## 12) ملاحظات وقيود معروفة

- **PostgreSQL** (إنتاج): لا تمرّر قائمة معاملات فارغة `()` لاستعلام يحوي `%` حرفياً (IndexError) — استخدم `None`. `lastrowid` يرجع 0 — استخدم `RETURNING id`. التواريخ تصل كـ `datetime` — استخدم فلاتر `dt_fmt`/`date` في القوالب.
- **الوحدة التخزينية** تحفظ الملفات (49MB/500MB حالياً) — راقب السعة؛ لا تصل ملفات الإنتاج عبر الملفات المحلية (`.dockerignore` يستثنيها).
- النشر عبر `railway up` يتطلب `< /dev/null` (§5).
- OAuth معطّل افتراضياً ما لم تُضبط المفاتيح.
