<div dir="rtl">

## Blazma Cyber 1.1.4

منصة أمن سيبراني دفاعي لـ Windows 10/11، محلية أولًا، بالعربي والإنجليزي. الشرح الكامل: [README.ar.md](https://github.com/mr-kateba/Blazma-Cyber/blob/claude/vibrant-sagan-xxz92l/README.ar.md)

### الجديد في 1.1.4
- **استعادة كلمة المرور صارت تعمل فعلًا:** John وhashcat لا يقرآن الأرشيف مباشرة، بل يحتاجان استخراج «هاش» الملف أولًا. صار البرنامج يفعل ذلك تلقائيًا بأدوات John (rar2john وzip2john)، ثم يشغّل المحرك على النتيجة. قبلها كانت كل محاولة تنتهي في 0.0 ثانية بلا نتيجة. (7z وPDF وOffice تحتاج أدوات John بلغة Perl/Python؛ RAR وZIP يعملان مباشرة.)

سابقًا في 1.1.3: التعرّف على RAR/7z/Office المحمية بكلمة مرور.

### التثبيت
1. نزّل `Blazma-Cyber-*-x64-setup.exe`.
2. المثبّت **غير موقّع بشهادة توقيع كود** بعد ← **Windows protected your PC** ← **More info** ثم **Run anyway**.
3. التثبيت للمستخدم الحالي، بلا صلاحيات مسؤول.

**بدون تثبيت:** `Blazma-Cyber-*-x64-portable.zip` — فكّ الضغط وشغّل `Blazma Cyber.exe`؛ البيانات في `Blazma-data` بجانبه.

### التحقق من الملف
- **مصدر البناء:** `gh attestation verify Blazma-Cyber-1.1.4-x64-setup.exe -R mr-kateba/Blazma-Cyber`
- **SHA-256:** قارن `Get-FileHash .\Blazma-Cyber-1.1.4-x64-setup.exe -Algorithm SHA256` بملف `SHA256SUMS.txt`.

### الحالة بصدق
- مُتحقَّق منه آليًا على Windows حقيقي: النظام، Defender، التوقيع الرقمي، التحليل الجنائي، الشبكة، pktmon، الواي فاي، الواجهة كاملة، وبناء المثبّت.
- **لم يُختبر بعد يدويًا:** الواي فاي على جهاز فيه كرت واي فاي، Nmap على Windows، التثبيت/الإزالة على سطح مكتب، فحص Defender السريع/الكامل، ومحركات John/hashcat الحقيقية.

</div>

---

## Blazma Cyber 1.1.4

Privacy-first, local-first, bilingual (Arabic/English) defensive cybersecurity workbench for Windows 10/11.

**New in 1.1.4**
- **Password recovery actually runs now:** John and hashcat can't read an archive directly — they need the file's "hash" extracted first. Blazma now does that automatically with John's own rar2john/zip2john tools, then runs the engine on the result. Before, every run finished in 0.0s finding nothing. (7z/PDF/Office need John's Perl/Python extractors; RAR and ZIP work out of the box.)

Earlier in 1.1.3: password-protected RAR/7z/Office are recognized.

- **Portable:** `Blazma-Cyber-*-x64-portable.zip` runs without installing; data stays in `Blazma-data` next to it.
- **Unsigned** (no certificate yet): SmartScreen → **More info → Run anyway**. Per-user install, no admin.
- **Verify provenance:** `gh attestation verify Blazma-Cyber-1.1.4-x64-setup.exe -R mr-kateba/Blazma-Cyber`.
- **Verify integrity:** compare `Get-FileHash <file> -Algorithm SHA256` with `SHA256SUMS.txt`.
- Verified automatically on real Windows in CI; not yet hand-tested: Wi-Fi hardware, Nmap on Windows, install/uninstall, Defender quick/full scans, real John/hashcat.
