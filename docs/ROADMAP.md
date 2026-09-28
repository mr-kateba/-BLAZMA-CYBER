# Roadmap

Status legend: **DONE** (works, connected, both languages, tested where practical) ·
**IN PROGRESS** · **TODO** · **BLOCKED**. Nothing is marked DONE unless it actually works.

## Phase 0 — Research — DONE
- DONE Repository inspection (empty repo, greenfield)
- DONE Stack evaluation → Electron + React + TypeScript (docs/ARCHITECTURE.md §2)
- DONE Engine/dependency research and license review (THIRD-PARTY-NOTICES.md, ARCHITECTURE §8)
- DONE Architecture and threat model

## Phase 1 — Foundation — DONE (core paths verified on Windows Server 2025 in CI)
- DONE Project structure, build (Vite + esbuild), typecheck, tests
- DONE Hardened Electron shell (sandbox, contextIsolation, CSP, IPC sender checks)
- DONE Design system (cards, stat cards, badges, gauges, sparkline, tables, tabs, toggles, dialogs, toasts, drop zone, skeletons, empty/error states)
- DONE Navigation (all sections; planned modules clearly labeled, no fake actions) + tool search
- DONE Arabic/English localization, RTL/LTR switching, LTR isolation of technical values, parity checks
- DONE First-launch language picker (persisted)
- DONE Dashboard with real local data (OS, CPU, RAM, disk, adapters, local IP, CPU history, processes, uptime); public IP only on explicit request
- DONE Settings (general, privacy, API keys, engines, about)
- DONE Structured logging with redaction
- DONE Local configuration (validated, atomic writes)
- DONE Privacy architecture: NetworkGate, Offline Mode (default ON), Network Activity log, clear-data controls
- DONE Secure API-key storage (Electron safeStorage / DPAPI; refuses plaintext)
- DONE PowerShell launcher `Start-Blazma.ps1`
- DONE Windows-only PowerShell paths verified on a real Windows machine (GitHub Actions windows-latest = Windows Server 2025, build 26100): system facts, Defender/firewall status, Authenticode, forensics collectors, network toolkit
- TODO Verify on a Windows 10/11 desktop: title-bar overlay look, Start-Blazma.ps1 launcher, installer install/uninstall

## Phase 2 — Local security
- DONE File Analyzer (static): streaming MD5/SHA-1/SHA-256/SHA-512, magic-byte type, MIME, timestamps, entropy, PE headers/sections/imports/exports/packer hints, IOC extraction, interesting strings, progress + cancel
- DONE Combined detection model with reasons and "incomplete" handling
- DONE Digital signature verification (Get-AuthenticodeSignature; verified on Windows in CI — also fixed a bug where an inherited PowerShell 7 PSModulePath made every result empty)
- DONE Hash Lab: text/file hashing, integrity verification, hash identification (ranked candidates), comparison
- DONE Quarantine: neutralized storage (XOR + .blazmaq + 0600), metadata, verified restore (SHA-256), restore-to, delete, rescan; tested end-to-end
- DONE YARA-X integration (official `yr` CLI adapter, tested against real YARA-X 1.20.0): engine detection/selection, rule manager, builtin starter pack, custom rules with `yr check` validation, local import, enable/disable, file & folder scans (recursive), results in File Analyzer and combined assessment
- DONE Security Center: Defender quick/full/file/folder scans (MpCmdRun, report-only for file/folder), threat history, quarantine UI — file scan (EICAR detection) and threat history verified on Windows in CI; quick/full scans not run in CI (duration)
- DONE Folder scanning (YARA-X; Defender folder scan on Windows)

## Phase 3 — Intelligence — DONE (with noted verification gaps)
- DONE IP Intelligence: scope classification, reverse DNS, RDAP (IANA bootstrap, gated redirects), ASN (Team Cymru via DNS), approximate geolocation (ipinfo.io), Tor exit check, reputation, per-source provenance; private IPs never leave the machine; "approximate location" notice
- DONE Domain Intelligence: DNS (A/AAAA/CNAME/MX/NS/TXT/CAA/SOA), SPF/DMARC, RDAP registration, TLS certificate (handshake only), hosting ASN; IDN/URL input normalization; young-domain warning
- DONE Reputation Center + adapters: VirusTotal (IP/domain/hash), AbuseIPDB, Shodan; hash-only file reputation in File Analyzer, folded into the assessment
- DONE All sources go through NetworkGate (HTTP, DNS, TLS) → Offline Mode + Network Activity
- Verification: DNS/ASN/TLS verified live; RDAP, ipinfo, Tor list and reputation APIs verified with fixtures/mocks only (HTTPS to those hosts is blocked in the build environment)
- TODO Censys adapter (API changed to Platform tokens; not implemented — a stored key is unused, stated in UI)
- TODO Use Electron `net.fetch` for system-proxy support (after verifying redirect: 'manual' semantics)

## Phase 4 — Forensics — DONE (Windows collectors verified in CI; USB history fixed for machines without USBSTOR)
- DONE Processes (PID/PPID, path, user, command line, start time, connection count, batch Authenticode check, "Analyze" → File Analyzer)
- DONE Connections (TCP/UDP, listening & established, owning process)
- DONE Services (binary path extraction, account, unquoted-service-path flag, signatures), drivers, startup commands, scheduled tasks (hide Microsoft), local users + Administrators membership (by SID, locale-independent), installed software (HKLM/HKCU, 32/64-bit), USB storage history, event logs (allow-listed logs, level filter), PowerShell history (explicit, warned, never logged)
- DONE Linux /proc fallbacks for processes and connections (verified live)
- DONE Network Toolkit: adapters (gateway, DNS), ping, traceroute, DNS + reverse DNS, TCP port check (<=1024 ports, bounded concurrency, authorization confirmation), routes, ARP/neighbors, device discovery (private attached subnet only, <= /24, authorization confirmation)
- DONE Public targets go through NetworkGate; local targets work in Offline Mode
- IN PROGRESS Per-function elevation: functions needing admin explain why (Security log, full process paths); an elevated helper process is not implemented yet
- Note: ping/traceroute use locale-independent PowerShell cmdlets on Windows (Test-Connection / Test-NetConnection); on Linux they require ping/traceroute to be installed (reported honestly when missing)

## Phase 5 — Recovery — DONE (engine runs need verification with a real John/hashcat install)
- DONE Encrypted-file detection (ZIP ZipCrypto/AES, 7z, RAR4/5, PDF RC4/AES-128/AES-256, Office OLE) — tested against a real ZipCrypto archive; also shown in File Analyzer
- DONE Password Recovery workspace for files the user owns: bring-your-own engine (John the Ripper / hashcat, user-selected executable, validated), wordlist / mask / candidate-list modes, explicit authorization checkbox, progress + rate + elapsed, stop, pause/resume (POSIX; reported as unavailable on Windows)
- DONE Recovered passwords are shown once in the UI and never written to logs or history (redaction covers `recovered`)
- DONE Session orchestration verified end-to-end with a stand-in engine fixture
- TODO Automatic hash extraction (`*2john`) inside Blazma; today the engine must accept the target directly or the user supplies the extracted hash
- TODO Hash Lab wordlist management

## Phase 6 — Investigation
- DONE Cases (CASE-YYYY-NNN), evidence vs. notes, auto timeline; "Add to case" from File Analyzer / IP / Domain intel
- DONE Threat Hunting: cross-module correlation (cases, quarantine, activity, network log, live processes/connections/services/startup, YARA rules) + persistence review flags
- DONE Reports: escaped, script-free HTML (strict CSP), JSON export, PDF via offline printToPDF; Arabic RTL / English LTR
- DONE OSINT accounts check: a username on 301 social networks (+338 other sites) with the WhatsMyName rules (pinned commit, CC BY-SA 4.0, adult/dating/political left out); strict found/missing signatures, everything else "couldn't check" with the reason; cancellable with progress; profile links re-derived in main. The Device Security Score no longer checks drive encryption (owner decision: people could turn BitLocker on without saving the recovery key)
- DONE OSINT workspace: domain/email/username/URL; Certificate Transparency (crt.sh), Wayback first/last snapshot, GitHub public profile, mail-domain DNS; provenance (endpoint + time) on every source; pivot links re-derived in main, opened only on click, gated. Verified with mocks + offline E2E — live sources were unreachable from the build sandbox

## Phase A (post-v0.1 plan, see chat report) — DONE
- DONE License GPL-3.0-or-later (LICENSE, shown by the installer)
- DONE Terminal opens the regular Windows terminal
- DONE Build hygiene: pages lazy-loaded (startup bundle 543 → 383 kB), Vite `import.meta.dirname`, actions/checkout + setup-node v5
- TODO (owner, GitHub settings) Rename the default branch to `main`

## Phase B — Regular users — DONE
- DONE B1 Device Security Score: 15 read-only checks (Defender, tamper protection, firewall, updates, UAC, SMBv1, RDP/NLA, Secure Boot, auto sign-in, Guest, LSA protection, memory integrity, PowerShell policy, TPM), unknown ≠ pass, plain-language why/fix, fixed "open Windows setting" links; dashboard hero with score + "Scan a file" / "Check a link"; verified on Windows in CI
- DONE B2 "What does this mean?": 24 plain-language explanations (Arabic + English) on the key cards of File Analyzer, Domain/IP Intelligence, Security Center, YARA, Hash Lab, Forensics, Threat Hunting and Offline Mode
- DONE B3 Simple/expert mode (chosen at first launch, switchable in the sidebar and Settings; simple = 8 essentials with friendlier labels and a lighter dashboard), drop a file anywhere to scan it, "What should I do?" advice under every file verdict, "Is this site trustworthy?" summary built only from retrieved facts

## Phase C — No external tools needed — DONE (verified on Windows in CI)
- DONE YARA-X 1.20.0, capa 9.4.0, Detect It Easy 3.21 bundled in the Windows installer (build-time download, pinned SHA-256)
- DONE ReversingLabs YARA pack (1,240 rules, MIT): compiled with YARA-X, zero false positives on Linux binaries; read-only pack in the rule manager; family rules = definitive, PUA = strong
- DONE File Analyzer: "What can this program do?" (capa, with MITRE ATT&CK IDs) and "Built with" (DIE); conservative evidence weights
- DONE Fixed: rule validation treated YARA-X warnings (exit code 2) and the word "error" in rule text as failures
- DONE Verified on Windows CI: engines fetched + SHA-256 verified; capa on notepad.exe → 30 capabilities / 11 ATT&CK techniques (49 s); DIE → Microsoft Linker 14.38 / MSVC 19.38; RL pack → 0 matches on 150 System32 files

## Phase D — Phishing & reputation — DONE
- DONE D1 "Check an email": local .eml / pasted-source analysis — sender consistency (display-name spoofing, Reply-To/Return-Path), SPF/DKIM/DMARC as recorded by the provider, real link destinations (mismatch, IP, @-trick, look-alike, shortener, http), risky attachments (executable, double extension, RTLO, macros, archives, HTML) with hand-off to File Analyzer under a non-executable name; Arabic encodings (RFC 2047/2231, windows-1256)
- DONE D2 "Was my password leaked?": Have I Been Pwned Pwned Passwords via k-anonymity (only a 5-char SHA-1 prefix is sent, with padding, through NetworkGate; matching is local; field cleared on submit; never logged or kept in history) + local observations while typing (length, character kinds, sequences, keyboard patterns, years) — no invented strength score
- DONE D3 abuse.ch: MalwareBazaar (hash), URLhaus (host/IP + payload hash) and ThreatFox (IOC/hash) in Reputation Center, IP/Domain Intelligence, File Analyzer and the "Is this site trustworthy?" summary; one free Auth-Key (DPAPI-stored); exact-hash listings are evidence (MalwareBazaar = malicious, ThreatFox by confidence, URLhaus payload = strong); "not listed" is never "clean"; SHA-1 skipped with a reason where unsupported. Parsers are tested against the documented response formats; not yet exercised against the live APIs with a real key

## Phase E — Deeper protection — DONE (verified on Windows CI: Hayabusa exported log 7 matches / live elevated 756 matches in 8 s; HollowsHunter 139 processes, 0 suspicious, 19 s)
- DONE E1 System proxy: NetworkGate's HTTP transport is Chromium's network stack (in-memory session, no cookies, no disk cache) — Windows proxy settings incl. PAC/WPAD and the Windows certificate store are honoured; manual redirects are returned to the gate hop by hop (Electron's fetch would cancel them, so they use net.request). Verified through an HTTP proxy on Linux (200/301/404/abort/POST). DNS queries and TLS certificate checks still connect directly
- DONE E2 "Signs of tampering" on Device Security: hosts file (security/update sites blocked or redirected = suspicious; ad-block style entries counted, not flagged), web proxy / PAC (PAC over http = suspicious), DNS servers of connected adapters (router and well-known providers fine, unknown public servers "check this"), user-added trusted root certificates (HKCU physical store, subject + thumbprint). Query-only script; hosts file read on every OS
- DONE E3 Browser extensions audit (Chrome, Edge, Brave, Vivaldi, Opera, Chromium, Firefox; read-only): what each extension may do (all sites, web traffic, cookies, history, clipboard, native programs, debugger, proxy…) and how it got there (store / folder or command line / another program / policy / unsigned). "Needs attention" = installed outside the store, unsigned or debugger — broad permissions alone are "broad access", not a verdict; removal steps per browser. Tested with fixture profiles (Chromium, Opera single profile, Firefox) and in the E2E
- DONE E4 Downloads watcher (opt-in, off by default): while Blazma is open, each finished download (partial .crdownload/.part/… names ignored, size must settle) is analyzed exactly like File Analyzer — read only, one at a time, bounded queue, never moved or deleted; dashboard card with recent results; a notification only for suspicious/malicious verdicts (click opens the analysis)
- DONE E5 Event-log hunting with bundled Hayabusa 4.1.0 (SHA-256 pinned; rules/.git pruned; AGPL + DRL license texts shipped): .evtx file or folder (unelevated, cancellable) or this computer (explained, then UAC — the only elevated action, engine-only, read-only); minimum level + period; summary by level and MITRE ATT&CK tactic, rules that matched (with rule authors, per DRL), most-severe-first matches. Verified locally with the Linux build on public attack samples (E2E); Windows CI runs it on an exported System log and live
- DONE E6 Memory implant scan with bundled HollowsHunter 0.4.1.1 (BSD-2, SHA-256 pinned): programs of the current user, `/quiet /json /ofilter 2` (no dumps; /kill and /suspend never used); summary parsed exactly as hh_report.cpp writes it; plain-language severity (hidden code / modified in memory / unusual) with false-positive guidance. Windows CI runs it on the runner's processes

## Phase F — Integration & portability — DONE
- DONE F1 IOC export: CSV (RFC 4180, spreadsheet-formula neutralized) and STIX 2.1 bundle (identity, one indicator per IOC with escaped patterns, grouping for the case) from a case's evidence — hashes (incl. file evidence hashes), IPv4/IPv6, domains, URLs, emails, file names
- DONE F2 MITRE ATT&CK: Enterprise ATT&CK 19.2 table generated from MITRE's official STIX data (scripts/make-attack-data.mjs; 697 techniques, 15 tactics, 146 revoked ids mapped to their replacements); event-log hunting shows an ATT&CK map by tactic with links to attack.mitre.org
- DONE F3 Portable mode: `portable.txt` next to the executable keeps all Blazma data and Chromium's own data in `Blazma-data` beside the program (own single-instance lock; read-only media fall back to the normal location); CI and releases build `*-x64-portable.zip` and smoke-test it in portable mode; Settings shows the copy type
- DONE F4 Manual update check (Settings → About): only on click, through NetworkGate (blocked in Offline Mode), reads this repository's GitHub release list, SemVer comparison incl. pre-releases; opens the release page built by the main process — nothing is downloaded or installed
- DECIDED F5: John the Ripper / hashcat stay user-installed and are not bundled (unchanged decision: password recovery is orchestration only, for files the user owns)

## Phase G — Network & everyday tools (v1.1.0) — DONE
- DONE G1 Device manufacturers: offline IEEE MA-L registry (npm oui-data, BSD-2) for neighbors, discovery, captures and Nmap; randomized (private) MAC addresses recognised as such
- DONE G2 Network traffic: pcap/pcapng reader and never-throwing packet parser (protocol readers adapted from the owner's MIT-licensed blazma.nt project), analyzer with devices/conversations/DNS/HTTPS names/cleartext and measured findings; short live capture via Windows pktmon (one UAC prompt, verified in Windows CI: 187 packets) or Wireshark dumpcap when installed; secrets never enter the report
- DONE G3 Wi-Fi Center: WLAN API reader (C# via Add-Type, numbers only → locale-independent), current connection, nearby networks, evil-twin/weak-signal/crowded-channel findings, saved networks exported WITHOUT keys; Windows 11 location privacy detected and explained (C# reader compile verified in Windows CI; real Wi-Fi hardware not available in CI)
- DONE G4 Service scan: user-installed Nmap with fixed unprivileged profiles (-sT, no NSE scripts), own networks only, authorization confirmation, XML parsing, risky-service findings (tested with real Nmap 7.94 on Linux; not bundled — same rule as John/hashcat)
- DONE G5 Light theme and "match Windows" (caption buttons follow the theme)
- DONE G6 Smart search (Ctrl+K): paste an indicator or path → the right tool, pre-filled; refangs hxxp/[.]
- DONE G7 File integrity monitor: folder fingerprints (SHA-256), added/removed/modified, hidden-timestamp edits, runnable files highlighted, suggested Windows persistence folders
- DONE G8 Full checkup: one click runs device security, tampering, extensions, Wi-Fi and watched folders (read-only) and gives one plain verdict; unavailable areas never count as ok
- DONE G9 Open ports on this PC: listening programs from the read-only connection table, who can reach them (this PC / network), plain names for well-known ports, remote access / file sharing / databases on the network flagged; part of the full checkup
- DONE G10 What starts with Windows: startup entries with the program's Authenticode signature/publisher, scope and location notes; unsigned programs in user folders and script launchers (rundll32, PowerShell, mshta…) are worth a look; opens Windows' Startup apps page to turn one off (Blazma never changes it); part of the full checkup; the dashboard remembers the last checkup
- TODO Verify on a real Wi-Fi PC and with Nmap installed on Windows (not available in CI)

## Phase H — Post-1.1 (v1.1.1) — DONE
- DONE Password recovery resource control (John --fork / hashcat -w and -D; fork count from os.cpus in main; re-validated; speed only)
- DONE New-device network watch: remember devices by MAC, flag never-seen ones on discovery, trust/forget; local baseline, cleared with activity
- DONE Fix: AppUserModelId + window icon so Windows shows the Blazma logo (taskbar/notifications)
- DONE Fix: pktmon 'Stop early' actually stops the elevated capture (stop-file, 1s steps)
- DONE Password recovery page links to official John/hashcat sites + setup steps

## Phase I — v1.1.2 — DONE
- DONE Full-checkup report: PDF/HTML (states, counts and reason codes only; validated in main; script-free CSP)
- DONE Outlook .msg in the email check: read-only CFB parser (bounds-checked, loop-safe) → MIME rebuilt from MAPI properties (original transport headers when present), byte-exact attachments, embedded messages; header values CR/LF-stripped and encoded; tested against a real Outlook file
- DONE QR Code Check: image read in main (20 MB, signature + header-only 50 MP limit), decoded in the sandboxed renderer (jsQR, Apache-2.0), payload classified (links, Wi-Fi, 2FA, payments, SMS, contacts…); secrets never returned, nothing opened
- DONE check-locales rejects single-brace placeholders
- DONE Fix: manual-redirect transport crashed the main process on non-Latin-1 response headers (emoji/Arabic) — headers converted losslessly, Location percent-encoded, callback errors become rejections (reproduced in Electron)

## v1.1.3 — DONE
- DONE Fix: encrypted-file detection reads the file's own structures — RAR5 file encryption records / archive encryption header, RAR 1.5-4 password flags, 7z index (AES coder; compressed index = undetermined), Office (EncryptionInfo agile/standard, Word FIB, Excel FILEPASS, PowerPoint EncryptedSummary); no more "every OLE file is encrypted"; tested on the 51 rarfile archives + real 7z/docx fixtures

## Phase 7 — Polish
- DONE Terminal: opens the regular Windows terminal (Windows Terminal, else PowerShell) in its own window — no in-app terminal by decision (the GUI never runs commands from user input)
- DONE Packaging config (electron-builder.yml): per-user NSIS (asInvoker, no elevation, Arabic + English installer), asar, hardened Electron fuses (RunAsNode off, NODE_OPTIONS/inspect off, asar integrity, only-load-from-asar), no publish/auto-update; app icon generated from the logo SVG (scripts/make-icon.mjs)
- DONE Packaged-app smoke test (scripts/package-smoke.mjs via CDP) — verified on Linux; `electron-builder --win --dir` also succeeds on Linux
- DONE Windows installer build: `npm run dist:win` builds the NSIS installer in CI and the packaged app passes the smoke test (installer uploaded as an unsigned artifact); install/uninstall on a desktop not yet tested
- TODO Code signing (certificate via CSC_LINK / CSC_KEY_PASSWORD env vars only; never committed)
- DONE Keyboard review: Escape closes dialogs (E2E-tested), dialogs labelled (aria-labelledby/-describedby), focus moves into dialogs, visible focus ring; full screen-reader audit still TODO
- DONE Final security review (see docs/AUDIT-REPORT.md §8): external links now gated + allowlisted, window.open fully denied, report paths contained, npm audit 0, no secrets in repo
- TODO Performance profiling; docs with screenshots from real Windows

## Proposed additions (from docs/AUDIT-REPORT.md §7) — now scheduled in Phases B–F
- DONE Device Security Score (Phase B)
- Tamper checks → Phase E2
- DONE Phishing email (.eml) analyzer (Phase D1)
- DONE Pwned Passwords check via k-anonymity (Phase D2)
- DONE "What does this mean?" educational explanations (Phase B)
- Downloads folder watcher, browser-extension audit → Phase E; DONE File Integrity Monitoring (Phase G7)
- MITRE ATT&CK mapping, IOC export (CSV/JSON/STIX 2.1), portable mode → Phase F; Sigma → Hayabusa (E5)
- DONE Windows CI (.github/workflows/ci.yml, windows-latest + ubuntu): unit tests incl. tests/windows-integration.test.ts (real PowerShell, Defender EICAR scan, Authenticode, forensics, network), full UI E2E, NSIS installer build + packaged smoke test — all green on Windows (run 3); the first runs found and fixed 2 real bugs (USB history without USBSTOR, PSModulePath breaking Authenticode)

## BLOCKED
- (none)
