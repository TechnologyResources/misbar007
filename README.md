# مسبار (Misbar) — أداة فحص الروابط

موقع ثنائي اللغة (عربي/إنجليزي) يفحص الروابط عبر:
1. **تحليل هيكلي فوري** — بدون أي مفاتيح API: IP مباشر، Punycode، رمز @، عدد النطاقات الفرعية، النطاقات العلوية المشبوهة، تشابه أسماء العلامات التجارية، الروابط المختصرة...
2. **اتصال فعلي بالموقع** عبر دالة Netlify Serverless: `dns.lookup`، طلب HTTP حقيقي مع تتبّع التحويلات، استخراج العنوان والوصف وأيقونة الموقع من HTML الفعلي.

شاشة الفحص تعرض بالضبط أسماء العمليات الحقيقية التي تُنفَّذ في الخلفية (`netlify/functions/analyze.mts`) — وليست حركة وهمية.

## هيكل المشروع
```
misbar/
├── netlify.toml
├── netlify/functions/analyze.mts   ← منطق الفحص الحقيقي (DNS + HTTP + heuristics)
└── public/
    ├── index.html
    ├── css/style.css
    └── js/app.js
```

## التشغيل محليًا
يتطلب [Netlify CLI](https://docs.netlify.com/cli/get-started/):
```bash
npm install -g netlify-cli
cd misbar
netlify dev
```
سيفتح الموقع على `http://localhost:8888` مع تشغيل دالة `/api/analyze` محليًا.

## النشر على Netlify
### الخيار الأول: من سطر الأوامر (الأسرع)
```bash
cd misbar
netlify deploy          # نشر تجريبي (Draft) للمعاينة
netlify deploy --prod   # نشر نهائي
```
أول مرة، سيطلب منك تسجيل الدخول وربط أو إنشاء موقع جديد.

### الخيار الثاني: عبر GitHub
1. ارفع مجلد `misbar` إلى مستودع جديد في حسابك على GitHub.
2. من لوحة تحكم Netlify: **Add new site → Import an existing project → GitHub** واختر المستودع.
3. Netlify سيكتشف `netlify.toml` تلقائيًا (مجلد النشر `public`، ودوال `netlify/functions`) — لا حاجة لأي إعداد إضافي.

> ملاحظة: النشر بالسحب والإفلات (drag-and-drop) على Netlify ينشر الملفات الثابتة فقط ولن يُفعّل دالة الفحص، لذلك يُفضّل أحد الخيارين أعلاه.

## تطوير لاحق (اختياري)
لرفع دقة الفحص لمستوى قواعد بيانات التهديدات العالمية، أضف مفتاح [VirusTotal](https://www.virustotal.com/gui/join-us) أو [Google Safe Browsing](https://developers.google.com/safe-browsing) كمتغيّر بيئة في Netlify (`Site configuration → Environment variables`)، ثم استدعِ الـ API من داخل `analyze.mts` وادمج النتيجة مع درجة الخطورة الحالية.
