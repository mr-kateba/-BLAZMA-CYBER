<div dir="rtl">

## Blazma Cyber 1.1.1

منصة أمن سيبراني دفاعي لـ Windows 10/11، محلية أولًا، بالعربي والإنجليزي. الشرح الكامل: [README.ar.md](https://github.com/mr-kateba/Blazma-Cyber/blob/claude/vibrant-sagan-xxz92l/README.ar.md)

### الجديد في 1.1.1
- **استعادة كلمة المرور — التحكم بموارد الجهاز:** اختر «متوازن» (يترك الجهاز صالحًا للاستخدام) أو «أقصى» (كل أنوية المعالج، ومع hashcat كرت الشاشة بالكامل) ليعمل المحرك أسرع على ملفاتك. ومع hashcat تختار المعالِج: تلقائي / كرت الشاشة / المعالج. يؤثّر على السرعة فقط، والنتيجة تبقى محلية ولا تُسجَّل.
- **تنبيه الأجهزة الجديدة في شبكتك:** عند اكتشاف الأجهزة، يعلّم البرنامج أي جهاز يظهر لأول مرة (جديد / شوهد سابقًا / موثوق)، ويعرض الأجهزة المحفوظة التي لم ترد. «وثّق كل الأجهزة الحالية» ليبرز الجديد الحقيقي فقط لاحقًا.
- **إصلاح شعار البرنامج:** يظهر شعار Blazma الآن في شريط المهام والإشعارات (بدل شعار Electron) — سواء ثبّتّه أو شغّلته من الكود المصدري.
- **زر «إيقاف مبكر» في تسجيل حركة الشبكة (pktmon)** صار يوقف التسجيل فورًا ويحلّل ما سُجّل، بدل الانتظار للنهاية.
- **صفحة استعادة كلمة المرور:** أزرار مباشرة للمواقع الرسمية لمحركي John the Ripper وhashcat، وخطوات التجهيز.

### التثبيت
1. نزّل `Blazma-Cyber-*-x64-setup.exe`.
2. المثبّت **غير موقّع بشهادة توقيع كود** بعد ← **Windows protected your PC** ← **More info** ثم **Run anyway**.
3. التثبيت للمستخدم الحالي، بلا صلاحيات مسؤول.

**بدون تثبيت:** `Blazma-Cyber-*-x64-portable.zip` — فكّ الضغط وشغّل `Blazma Cyber.exe`؛ البيانات في `Blazma-data` بجانبه.

### التحقق من الملف
- **مصدر البناء:** `gh attestation verify Blazma-Cyber-1.1.1-x64-setup.exe -R mr-kateba/Blazma-Cyber`
- **SHA-256:** قارن `Get-FileHash .\Blazma-Cyber-1.1.1-x64-setup.exe -Algorithm SHA256` بملف `SHA256SUMS.txt`.

### الحالة بصدق
- مُتحقَّق منه آليًا على Windows حقيقي: النظام، Defender، التوقيع الرقمي، التحليل الجنائي، الشبكة، pktmon، الواي فاي، الواجهة كاملة، وبناء المثبّت.
- **لم يُختبر بعد يدويًا:** الواي فاي على جهاز فيه كرت واي فاي، Nmap على Windows، التثبيت/الإزالة على سطح مكتب، فحص Defender السريع/الكامل، ومحركات John/hashcat الحقيقية.

</div>

---

## Blazma Cyber 1.1.1

Privacy-first, local-first, bilingual (Arabic/English) defensive cybersecurity workbench for Windows 10/11.

**New in 1.1.1**
- **Password recovery — resource control:** choose Balanced (keeps the computer usable) or Maximum (every CPU core; with hashcat, full graphics-card workload) so the engine works faster on your own files; with hashcat, pick the processor (Automatic / Graphics card / CPU). Speed only — the result stays local and is never logged.
- **New-device alert on your network:** discovery marks each device New / Seen before / Trusted and lists saved devices that did not answer; "Trust all current devices" so only genuinely new ones stand out next time.
- **Icon fix:** the Blazma logo now shows on the taskbar and in notifications (not Electron's), whether installed or run from source.
- **"Stop early" for pktmon captures** now stops the recording immediately and analyses what was captured.
- **Password recovery page:** direct links to the official John the Ripper and hashcat sites, with setup steps.

- **Portable:** `Blazma-Cyber-*-x64-portable.zip` runs without installing; data stays in `Blazma-data` next to it.
- **Unsigned** (no certificate yet): SmartScreen → **More info → Run anyway**. Per-user install, no admin.
- **Verify provenance:** `gh attestation verify Blazma-Cyber-1.1.1-x64-setup.exe -R mr-kateba/Blazma-Cyber`.
- **Verify integrity:** compare `Get-FileHash <file> -Algorithm SHA256` with `SHA256SUMS.txt`.
- Verified automatically on real Windows in CI; not yet hand-tested: Wi-Fi hardware, Nmap on Windows, install/uninstall, Defender quick/full scans, real John/hashcat.
