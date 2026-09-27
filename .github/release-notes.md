<div dir="rtl">

## Blazma Cyber 1.0.1

منصة أمن سيبراني دفاعي لـ Windows 10/11، محلية أولًا، بالعربي والإنجليزي. الشرح الكامل: [README.ar.md](https://github.com/mr-kateba/Blazma-Cyber/blob/claude/vibrant-sagan-xxz92l/README.ar.md)

### الجديد في 1.0.1
- **البحث عن اسم مستخدم في 301 موقع تواصل اجتماعي** (و338 موقعًا آخر اختياريًا): موجود / غير موجود / تعذّر الفحص مع السبب — بدون تخمين.
- روابط مباشرة لفيسبوك وإنستغرام وتيك توك ويوتيوب وتيليجرام.
- حذف فحص تشفير القرص (BitLocker) من «أمان جهازي».
- إصلاحات في الواجهة: أزرار النافذة لم تعد تغطي الشريط العلوي في الواجهة العربية، بطاقات بعرض كامل، شارات حالة أوضح.

### التثبيت
1. نزّل `Blazma-Cyber-*-x64-setup.exe` من الملفات بالأسفل.
2. المثبّت **غير موقّع بشهادة توقيع كود** بعد، لذلك ستظهر رسالة **Windows protected your PC** ← اضغط **More info** ثم **Run anyway**.
3. التثبيت للمستخدم الحالي، ولا يحتاج صلاحيات المسؤول.

**بدون تثبيت (نسخة محمولة):** نزّل `Blazma-Cyber-*-x64-portable.zip`، فكّ الضغط في أي مجلد (أو ذاكرة USB)، وشغّل `Blazma Cyber.exe`. كل البيانات تبقى في مجلد `Blazma-data` بجانبه.

### التحقق من سلامة الملف
- **شهادة مصدر البناء (Build provenance):** تثبت أن الملف بُني من هذا المستودع عبر GitHub Actions ولم يُعدَّل بعدها:
  `gh attestation verify Blazma-Cyber-1.0.1-x64-setup.exe -R mr-kateba/Blazma-Cyber`
- **SHA-256:** قارن الناتج بالقيمة بالأسفل وبملف `SHA256SUMS.txt`:
  `Get-FileHash .\Blazma-Cyber-1.0.1-x64-setup.exe -Algorithm SHA256`

### الحالة بصدق
- مُتحقَّق منه آليًا على Windows حقيقي (Server 2025): استعلامات النظام، Defender، التوقيع الرقمي، التحليل الجنائي، الشبكة، الواجهة كاملة، وبناء المثبّت.
- **لم يُختبر بعد يدويًا على جهاز Windows 10/11:** التثبيت والإزالة، شريط العنوان، فحص Defender السريع/الكامل، ومحركات John/hashcat الحقيقية.
- زر **الطرفية** يفتح طرفية Windows العادية في نافذة منفصلة.

</div>

---

## Blazma Cyber 1.0.1

Privacy-first, local-first, bilingual (Arabic/English) defensive cybersecurity workbench for Windows 10/11.

**New in 1.0.1:** username search on 301 social networks (+338 other sites, optional) with found / not found / couldn't check — never guessed; direct links for Facebook, Instagram, TikTok, YouTube and Telegram; the drive-encryption (BitLocker) check is removed; UI fixes (caption buttons no longer cover the top bar in Arabic, full-width single cards, clearer status badges).

- **Portable:** `Blazma-Cyber-*-x64-portable.zip` runs without installing (unzip anywhere, e.g. a USB drive); all data stays in `Blazma-data` next to the program.
- **Unsigned** (no code-signing certificate yet): SmartScreen shows *Windows protected your PC* → **More info → Run anyway**. Per-user install, no administrator rights.
- **Verify provenance:** `gh attestation verify Blazma-Cyber-1.0.1-x64-setup.exe -R mr-kateba/Blazma-Cyber` (GitHub build-provenance attestation, Sigstore).
- **Verify integrity:** compare `Get-FileHash <file> -Algorithm SHA256` with `SHA256SUMS.txt` / the value below.
- Verified automatically on real Windows (Server 2025) in CI; not yet hand-tested on a Windows 10/11 desktop (install/uninstall, title bar, Defender quick/full scans, real John/hashcat).
