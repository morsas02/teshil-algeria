# مشروع تسهيل — ta9eef-algeria

## قواعد إلزامية

### حماية بيانات المستخدمين (الأولوية القصوى)
- قبل أي تعديل في الكود أو قاعدة البيانات أو أي إجراء قد يؤثر على بيانات المستخدمين،
  يجب **دائمًا أخذ نسخة احتياطية** من بياناتهم والمحافظة عليها.
- لا يتم حذف أو تغيير أو إعادة إنشاء أي جدول/بيانات مستخدمين دون حفظ نسخة أولاً.
- عند التعديل في بنية قاعدة البيانات (schema/migration)، يُحفظ النسخ الاحتياطي
  في مكان آمن خارج مجلد المشروع (مثال: `/Users/dz/ta9eef-algeria-backups` أو
  مجلد مؤقت ثم يؤكد المستخدم).
- تحذير مهم: Railway يعمل بـ SQLite بدون قرص دائم، وأي `deploy` جديد يصفّر البيانات.
  لا يتم النشر دون التذكير/التحقق من حفظ البيانات إن وُجدت بيانات إنتاج حقيقية.
- عند إضافة ميزة جديدة تُعدّل بيانات المستخدم، تُبنى الميزة بطريقة لا تفقد البيانات
  الحالية أبداً (إضافة أعمدة nullable جديدة بدل حذف الجداول، إلخ).

## بيئة الإنتاج (Railway)

- **الموقع**: https://talented-respect-production.up.railway.app (مشروع `teshil`، بيئة production، خدمة `talented-respect`).
- **قاعدة البيانات**: PostgreSQL على Railway (خدمة "Postgres"). بيانات الإنتاج لا تُصفّر عند النشر.
- **الملفات المرفوعة** (صور/إيصالات/نسخ احتياطية) تُحفظ في وحدة تخزين دائمة `talented-respect-volume`
  مركّبة في `/app/storage`، ومتغير البيئة `STORAGE_ROOT=/app/storage`. لا تصل الملفات عبر الـ container العابر.
- **النشر**: من مجلد المشروع:
  `railway up --service talented-respect -y -e production -w "anisztn's Projects"`
  (يجب تمرير `-w "anisztn's Projects"` وإلا ينتظر اختيار الـ workspace بصمت ويعلق عند "Indexing..." في الجلسات غير التفاعلية.
  يمكن إضافة `--detach` ثم متابعة الحالة بـ `railway deployment list`). النشر عبر دفع GitHub لا يعمل بشكل موثوق.
- **نسخ احتياطي تلقائي**: التطبيق يكتب يومياً `STORAGE_ROOT/backups/ta9eef-data-*.json` (يحتفظ بآخر 7) عبر
  خيط خلفية `_daily_loop`. كما يمكن للمدير تنزيل نسخة يدوية من `/admin/backup`.
- **قاعدة قبل أي تعديل على بيانات الإنتاج**: أخذ نسخة من `/admin/backup` أو JSON dump أولاً،
  وحفظها في `/Users/dz/ta9eef-algeria-backups`.

## البريد الإلكتروني (Brevo)

- Railway يحجب منافذ SMTP (25/465/587) — إرسال عبر Gmail SMTP لا يعمل من الإنتاج أبداً.
- البريد يُرسل عبر **Brevo API** (HTTPS/443): متغيرات `BREVO_API_KEY` و`BREVO_SENDER` و`BREVO_SENDER_NAME`
  مضبوطة على Railway. المرسل الثابت: `morsizitouni132@gmail.com` (موثّق في Brevo).
- في Brevo: تأكد أن خيار "Restrict API calls to authorised IPs only" معطّل (وإلا يُرفض الطلب بـ 401).
- الإرسال يتم في خيط خلفية بمهلة 15 ثانية حتى لا يُعلّق الطلب أو يُقتل الـ worker.
- حالياً البريد يُستخدم فقط في "نسيت كلمة المرور" عبر `send_email()` في `app.py`.

## ملاحظات تقنية

- عند العمل مع PostgreSQL: لا تمرّر قائمة معاملات فارغة `()` لاستعلامات تحتوي `%` حرفياً (IndexError)،
  استخدم `None`. و`lastrowid` يرجع 0 في psycopg2 — استخدم `RETURNING id`. وtimestamps تصل ككائنات
  datetime — استخدم فلاتر `dt_fmt`/`date` في القوالب بدل تقطيع `[:16]`.
- `.dockerignore` يستثني `static/uploads/` و`static/receipts/` و`static/backups/` — لا تعتمد على نقل
  الملفات المحلية عند النشر؛ الملفات الحقيقية على الوحدة التخزينية.
