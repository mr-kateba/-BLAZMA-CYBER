<div dir="rtl">

## Blazma Cyber 1.1.2

منصة أمن سيبراني دفاعي لـ Windows 10/11، محلية أولًا، بالعربي والإنجليزي. الشرح الكامل: [README.ar.md](https://github.com/mr-kateba/Blazma-Cyber/blob/claude/vibrant-sagan-xxz92l/README.ar.md)

### الجديد في 1.1.2
- **افحص رمز QR قبل أن تمسحه:** أفلت صورة أو لقطة شاشة أو الصقها (Ctrl+V) لترى ماذا يحتوي الرمز: رابط (عنوان IP، موقع مقلّد أو مختصر، غير مشفّر)، دخول شبكة واي فاي، رمز تحقق بخطوتين، طلب دفع بعملة رقمية، رسالة SMS مدفوعة. لا يُفتح أي شيء، ولا تُعرض كلمات مرور الواي فاي ولا أسرار التحقق.
- **ملفات Outlook ‏‎.msg في «افحص رسالة بريد»:** اسحب الرسالة من Outlook وأفلتها — نفس فحص التصيّد (الترويسات، الروابط، المرفقات، الرسائل المرفقة).
- **تقرير الفحص الشامل:** احفظ النتيجة PDF أو HTML.

### التثبيت
1. نزّل `Blazma-Cyber-*-x64-setup.exe`.
2. المثبّت **غير موقّع بشهادة توقيع كود** بعد ← **Windows protected your PC** ← **More info** ثم **Run anyway**.
3. التثبيت للمستخدم الحالي، بلا صلاحيات مسؤول.

**بدون تثبيت:** `Blazma-Cyber-*-x64-portable.zip` — فكّ الضغط وشغّل `Blazma Cyber.exe`؛ البيانات في `Blazma-data` بجانبه.

### التحقق من الملف
- **مصدر البناء:** `gh attestation verify Blazma-Cyber-1.1.2-x64-setup.exe -R mr-kateba/Blazma-Cyber`
- **SHA-256:** قارن `Get-FileHash .\Blazma-Cyber-1.1.2-x64-setup.exe -Algorithm SHA256` بملف `SHA256SUMS.txt`.

### الحالة بصدق
- مُتحقَّق منه آليًا على Windows حقيقي: النظام، Defender، التوقيع الرقمي، التحليل الجنائي، الشبكة، pktmon، الواي فاي، الواجهة كاملة، وبناء المثبّت.
- **لم يُختبر بعد يدويًا:** الواي فاي على جهاز فيه كرت واي فاي، Nmap على Windows، التثبيت/الإزالة على سطح مكتب، فحص Defender السريع/الكامل، ومحركات John/hashcat الحقيقية.

</div>

---

## Blazma Cyber 1.1.2

Privacy-first, local-first, bilingual (Arabic/English) defensive cybersecurity workbench for Windows 10/11.

**New in 1.1.2**
- **QR Code Check:** drop, browse or paste (Ctrl+V) a picture of a QR code and see what it contains before scanning it — link warnings (IP address, look-alike or shortened site, unencrypted), Wi-Fi logins, 2FA setup codes, crypto payment requests, premium SMS. Nothing is opened; Wi-Fi passwords and 2FA secrets are never shown.
- **Outlook `.msg` files in "Check an email":** drag a message out of Outlook and drop it — the same phishing analysis (headers, links, attachments, attached emails).
- **Full checkup report:** save the result as PDF or HTML.

- **Portable:** `Blazma-Cyber-*-x64-portable.zip` runs without installing; data stays in `Blazma-data` next to it.
- **Unsigned** (no certificate yet): SmartScreen → **More info → Run anyway**. Per-user install, no admin.
- **Verify provenance:** `gh attestation verify Blazma-Cyber-1.1.2-x64-setup.exe -R mr-kateba/Blazma-Cyber`.
- **Verify integrity:** compare `Get-FileHash <file> -Algorithm SHA256` with `SHA256SUMS.txt`.
- Verified automatically on real Windows in CI; not yet hand-tested: Wi-Fi hardware, Nmap on Windows, install/uninstall, Defender quick/full scans, real John/hashcat.
