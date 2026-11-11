# NexaBox — مشروع مستودع المشاريع

## إصلاح النشر على GitHub Pages
هذه الحزمة مجهزة الآن بسير عمل GitHub Actions للنشر التلقائي.

### طريقة الرفع الصحيحة
1. فك ضغط ZIP على الهاتف.
2. افتح مستودع GitHub الخاص بك.
3. ارفع **كل محتويات المجلد مباشرة إلى جذر المستودع**. يجب أن يظهر `index.html` بجانب مجلد `assets` وملف `manifest.webmanifest`، ويجب أن يظهر مجلد `.github/workflows` أيضاً.
4. نفّذ Commit إلى الفرع `main` (أو `master`).
5. افتح تبويب Actions وانتظر اكتمال `Publish NexaBox to GitHub Pages` بنجاح.
6. من Settings ثم Pages اختر Source: **GitHub Actions**. لا تختر Deploy from a branch عند استخدام هذا الإعداد.
7. افتح رابط Pages الذي يظهر في تفاصيل عملية النشر.

> لا ترفع ملف ZIP نفسه داخل المستودع وتتوقع تشغيله. GitHub Pages ينشر ملفات الموقع بعد فك ضغطها ورفع محتوياتها.

## وظائف النسخة
- واجهة عربية RTL.
- إضافة مشروع واسم وإصدار وتاريخ تحديث ووصف.
- إرفاق ZIP وAPK.
- حفظ محلي في IndexedDB.
- واجهة ربط Supabase للحسابات والتخزين السحابي.

## التخزين السحابي
يلزم إعداد مشروع Supabase وتنفيذ `supabase/schema.sql` ثم إدخال Project URL وPublic anon/publishable key من داخل التطبيق. لا تضع service_role key في الواجهة.

## فحص تقني
- `index.html` في جذر المشروع.
- `.nojekyll` موجود.
- GitHub Actions workflow للنشر موجود في `.github/workflows/pages.yml`.
- JavaScript syntax checked with Node.js.

## حدود مهمة
هذه حزمة تطبيق ويب/PWA وليست APK أندرويد. التخزين المحلي خاص بالمتصفح والجهاز. مزامنة الحسابات والملفات تتطلب إعداد Supabase. لا يوجد حساب سحابي مُنشأ تلقائياً.
