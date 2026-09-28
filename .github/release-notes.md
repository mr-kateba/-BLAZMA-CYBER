<div dir="rtl">

## Blazma Cyber 1.1.3

منصة أمن سيبراني دفاعي لـ Windows 10/11، محلية أولًا، بالعربي والإنجليزي. الشرح الكامل: [README.ar.md](https://github.com/mr-kateba/Blazma-Cyber/blob/claude/vibrant-sagan-xxz92l/README.ar.md)

### الجديد في 1.1.3
- **التعرّف على ملفات RAR المحمية بكلمة مرور:** ملف RAR تحتاج ملفاته كلمة مرور لكن أسماءها ظاهرة (الافتراضي في WinRAR) كان يظهر «غير مشفّر». صار البرنامج يقرأ محتويات الأرشيف نفسها — RAR5 وRAR القديم، مع تشفير الأسماء أو بدونه — وكذلك 7z ومستندات Office 97-2003. وإذا تعذّر التأكد تخبرك الصفحة وتسمح لك بالمتابعة.
- **إصلاح:** ملفات Office القديمة وملفات التثبيت ورسائل Outlook كانت تظهر خطأً «مشفّرة» في محلل الملفات.

سابقًا في 1.1.2: فحص رموز QR، ملفات Outlook ‏‎.msg، تقرير الفحص الشامل، وإصلاح تعطّل فحص الحسابات.

### التثبيت
1. نزّل `Blazma-Cyber-*-x64-setup.exe`.
2. المثبّت **غير موقّع بشهادة توقيع كود** بعد ← **Windows protected your PC** ← **More info** ثم **Run anyway**.
3. التثبيت للمستخدم الحالي، بلا صلاحيات مسؤول.

**بدون تثبيت:** `Blazma-Cyber-*-x64-portable.zip` — فكّ الضغط وشغّل `Blazma Cyber.exe`؛ البيانات في `Blazma-data` بجانبه.

### التحقق من الملف
- **مصدر البناء:** `gh attestation verify Blazma-Cyber-1.1.3-x64-setup.exe -R mr-kateba/Blazma-Cyber`
- **SHA-256:** قارن `Get-FileHash .\Blazma-Cyber-1.1.3-x64-setup.exe -Algorithm SHA256` بملف `SHA256SUMS.txt`.

### الحالة بصدق
- مُتحقَّق منه آليًا على Windows حقيقي: النظام، Defender، التوقيع الرقمي، التحليل الجنائي، الشبكة، pktmon، الواي فاي، الواجهة كاملة، وبناء المثبّت.
- **لم يُختبر بعد يدويًا:** الواي فاي على جهاز فيه كرت واي فاي، Nmap على Windows، التثبيت/الإزالة على سطح مكتب، فحص Defender السريع/الكامل، ومحركات John/hashcat الحقيقية.

</div>

---

## Blazma Cyber 1.1.3

Privacy-first, local-first, bilingual (Arabic/English) defensive cybersecurity workbench for Windows 10/11.

**New in 1.1.3**
- **Password-protected RAR files are recognized:** a RAR whose files need a password but whose names are visible (WinRAR's default) was shown as "not encrypted". Blazma now reads the archive's own entries — RAR5 and RAR 1.5–4, with or without encrypted names — and 7z archives and Office 97-2003 documents too. When a file can't confirm either way, the page says so and still lets you continue.
- **Fix:** old-format Office files, installers and Outlook messages were wrongly shown as "encrypted" in the File Analyzer.

Earlier in 1.1.2: QR Code Check, Outlook `.msg` files, checkup report, OSINT crash fix.

- **Portable:** `Blazma-Cyber-*-x64-portable.zip` runs without installing; data stays in `Blazma-data` next to it.
- **Unsigned** (no certificate yet): SmartScreen → **More info → Run anyway**. Per-user install, no admin.
- **Verify provenance:** `gh attestation verify Blazma-Cyber-1.1.3-x64-setup.exe -R mr-kateba/Blazma-Cyber`.
- **Verify integrity:** compare `Get-FileHash <file> -Algorithm SHA256` with `SHA256SUMS.txt`.
- Verified automatically on real Windows in CI; not yet hand-tested: Wi-Fi hardware, Nmap on Windows, install/uninstall, Defender quick/full scans, real John/hashcat.
