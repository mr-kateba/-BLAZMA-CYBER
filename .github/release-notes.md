<div dir="rtl">

## Blazma Cyber 1.1.0

منصة أمن سيبراني دفاعي لـ Windows 10/11، محلية أولًا، بالعربي والإنجليزي. الشرح الكامل: [README.ar.md](https://github.com/mr-kateba/Blazma-Cyber/blob/claude/vibrant-sagan-xxz92l/README.ar.md)

### الجديد في 1.1.0
- **الواي فاي:** أمان اتصالك الحالي بكلام بسيط (WPA3/WPA2/مفتوحة)، قوة الإشارة والقناة والسرعة، الشبكات القريبة مع كشف **الشبكة المنتحِلة (Evil Twin)** وازدحام القنوات، ومراجعة الشبكات المحفوظة (المفتوحة التي تتصل تلقائيًا، الضعيفة، المخفية) — **بدون قراءة كلمات المرور أبدًا**.
- **حركة الشبكة:** حلّل ملفات Wireshark (pcap/pcapng) أو سجّل من 15 ثانية إلى 5 دقائق بأداة pktmon المدمجة في Windows (نافذة UAC واحدة) أو بـ Wireshark إن كان مثبّتًا: الأجهزة وشركاتها المصنّعة، المحادثات، DNS، مواقع HTTPS، تسجيلات الدخول غير المشفّرة، وأنماط مثل فحص المنافذ وانتحال ARP وخادم DHCP دخيل وTLS قديم. الكوكيز وكلمات المرور ومحتوى الصفحات لا تدخل التقرير.
- **فحص الخدمات (Nmap):** إذا ثبّتّ Nmap من nmap.org: من المتصل بشبكتك وما الخدمات المفتوحة على كل جهاز (100 أو 1000 منفذ) مع شرح الخطورة (Telnet، قواعد بيانات مكشوفة، VNC، سطح المكتب البعيد…). لشبكاتك أنت فقط، وبعد تأكيد التصريح.
- **المنافذ المفتوحة على جهازك:** أي البرامج تنتظر اتصالات، وهل يصل إليها جهازك فقط أم الشبكة، مع اسم مفهوم لكل منفذ معروف وتنبيه لخدمات الوصول البعيد ومشاركة الملفات وقواعد البيانات المكشوفة.
- **مراقبة سلامة الملفات:** خذ بصمة SHA-256 لمجلد ثم اعرف بدقة ما أُضيف أو حُذف أو تغيّر — حتى لو أُعيد التاريخ القديم للملف لإخفاء التعديل. أماكن مقترحة: مجلدات بدء التشغيل، ملف hosts، ملفات PowerShell.
- **فحص شامل بضغطة واحدة:** أمان الجهاز، علامات العبث، إضافات المتصفح، الواي فاي والمجلدات المراقَبة — بنتيجة واحدة واضحة ورابط لتفاصيل كل قسم.
- **البحث الذكي (Ctrl+K):** الصق IP أو هاش أو نطاقًا أو رابطًا أو بريدًا أو @اسم مستخدم أو مسار ملف (حتى المكتوب بصيغة `hxxp` و`[.]`) وانتقل مباشرة للأداة المناسبة والقيمة جاهزة.
- **أسماء الشركات المصنّعة للأجهزة** (من سجل IEEE، بدون إنترنت) في جيران الشبكة واكتشاف الأجهزة.
- **سمة فاتحة** وخيار «مثل إعداد Windows» (أزرار النافذة تتبع السمة).

### التثبيت
1. نزّل `Blazma-Cyber-*-x64-setup.exe` من الملفات بالأسفل.
2. المثبّت **غير موقّع بشهادة توقيع كود** بعد، لذلك ستظهر رسالة **Windows protected your PC** ← اضغط **More info** ثم **Run anyway**.
3. التثبيت للمستخدم الحالي، ولا يحتاج صلاحيات المسؤول.

**بدون تثبيت (نسخة محمولة):** نزّل `Blazma-Cyber-*-x64-portable.zip`، فكّ الضغط في أي مجلد (أو ذاكرة USB)، وشغّل `Blazma Cyber.exe`. كل البيانات تبقى في مجلد `Blazma-data` بجانبه.

### التحقق من سلامة الملف
- **شهادة مصدر البناء (Build provenance):** تثبت أن الملف بُني من هذا المستودع عبر GitHub Actions ولم يُعدَّل بعدها:
  `gh attestation verify Blazma-Cyber-1.1.0-x64-setup.exe -R mr-kateba/Blazma-Cyber`
- **SHA-256:** قارن الناتج بالقيمة بالأسفل وبملف `SHA256SUMS.txt`:
  `Get-FileHash .\Blazma-Cyber-1.1.0-x64-setup.exe -Algorithm SHA256`

### الحالة بصدق
- مُتحقَّق منه آليًا على Windows حقيقي (Server 2025): استعلامات النظام، Defender، التوقيع الرقمي، التحليل الجنائي، الشبكة، **تسجيل حركة الشبكة بـ pktmon**، قارئ الواي فاي، الواجهة كاملة، وبناء المثبّت.
- **لم يُختبر بعد يدويًا:** الواي فاي على جهاز فيه كرت واي فاي حقيقي، Nmap على Windows، التثبيت والإزالة على Windows 10/11، فحص Defender السريع/الكامل، ومحركات John/hashcat الحقيقية.

</div>

---

## Blazma Cyber 1.1.0

Privacy-first, local-first, bilingual (Arabic/English) defensive cybersecurity workbench for Windows 10/11.

**New in 1.1.0**
- **Wi-Fi:** current connection security in plain words, signal/band/channel/speed, nearby networks with an **evil-twin** check and a channel chart, and an audit of saved networks — passwords are never read.
- **Network traffic:** analyse .pcap/.pcapng files or record 15 s – 5 min with built-in Windows pktmon (one UAC prompt) or Wireshark's dumpcap: devices with manufacturers, conversations, DNS, HTTPS sites, unencrypted logins, and measured patterns (port scan, ARP conflict, rogue DHCP, outdated TLS…). Cookies, passwords and page contents never enter the report.
- **Service scan (Nmap):** with your own Nmap install, who is online and which services each device exposes, with plain-language risks — your own networks only, after an authorization confirmation.
- **Open ports on this PC:** which programs wait for connections and whether only this PC or the network can reach them, with plain names for well-known ports.
- **File integrity monitor:** fingerprint a folder (SHA-256), then see exactly what was added, removed or changed — including edits that restored the old timestamp.
- **Full checkup:** one click — device security, signs of tampering, browser extensions, Wi-Fi and watched folders, one plain verdict.
- **Smart search (Ctrl+K):** paste an IP, hash, domain, link, e-mail, @username or file path (defanged `hxxp`/`[.]` too) and jump to the right tool, pre-filled.
- **Device manufacturers** (offline IEEE registry) in neighbors and discovery; **light theme** and *match Windows*.

- **Portable:** `Blazma-Cyber-*-x64-portable.zip` runs without installing (unzip anywhere, e.g. a USB drive); all data stays in `Blazma-data` next to the program.
- **Unsigned** (no code-signing certificate yet): SmartScreen shows *Windows protected your PC* → **More info → Run anyway**. Per-user install, no administrator rights.
- **Verify provenance:** `gh attestation verify Blazma-Cyber-1.1.0-x64-setup.exe -R mr-kateba/Blazma-Cyber` (GitHub build-provenance attestation, Sigstore).
- **Verify integrity:** compare `Get-FileHash <file> -Algorithm SHA256` with `SHA256SUMS.txt` / the value below.
- Verified automatically on real Windows (Server 2025) in CI, including a real pktmon capture and the Wi-Fi reader; not yet hand-tested: Wi-Fi on real Wi-Fi hardware, Nmap on Windows, install/uninstall on a Windows 10/11 desktop, Defender quick/full scans, real John/hashcat.
