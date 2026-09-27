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
- TODO Automatic hash extraction (`*2john`) inside BLAZMA; today the engine must accept the target directly or the user supplies the extracted hash
- TODO Hash Lab wordlist management

## Phase 6 — Investigation
- DONE Cases (CASE-YYYY-NNN), evidence vs. notes, auto timeline; "Add to case" from File Analyzer / IP / Domain intel
- DONE Threat Hunting: cross-module correlation (cases, quarantine, activity, network log, live processes/connections/services/startup, YARA rules) + persistence review flags
- DONE Reports: escaped, script-free HTML (strict CSP), JSON export, PDF via offline printToPDF; Arabic RTL / English LTR
- DONE OSINT workspace: domain/email/username/URL; Certificate Transparency (crt.sh), Wayback first/last snapshot, GitHub public profile, mail-domain DNS; provenance (endpoint + time) on every source; pivot links re-derived in main, opened only on click, gated. Verified with mocks + offline E2E — live sources were unreachable from the build sandbox

## Phase A (post-v0.1 plan, see chat report) — DONE
- DONE License GPL-3.0-or-later (LICENSE, shown by the installer)
- DONE Terminal opens the regular Windows terminal
- DONE Build hygiene: pages lazy-loaded (startup bundle 543 → 383 kB), Vite `import.meta.dirname`, actions/checkout + setup-node v5
- TODO (owner, GitHub settings) Rename the default branch to `main`

## Phase B — Regular users — DONE
- DONE B1 Device Security Score: 16 read-only checks (Defender, tamper protection, firewall, updates, UAC, SMBv1, RDP/NLA, Secure Boot, drive encryption, auto sign-in, Guest, LSA protection, memory integrity, PowerShell policy, TPM), unknown ≠ pass, plain-language why/fix, fixed "open Windows setting" links; dashboard hero with score + "Scan a file" / "Check a link"; verified on Windows in CI
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

## Phase E — Deeper protection — IN PROGRESS
- DONE E1 System proxy: NetworkGate's HTTP transport is Chromium's network stack (in-memory session, no cookies, no disk cache) — Windows proxy settings incl. PAC/WPAD and the Windows certificate store are honoured; manual redirects are returned to the gate hop by hop (Electron's fetch would cancel them, so they use net.request). Verified through an HTTP proxy on Linux (200/301/404/abort/POST). DNS queries and TLS certificate checks still connect directly
- DONE E2 "Signs of tampering" on Device Security: hosts file (security/update sites blocked or redirected = suspicious; ad-block style entries counted, not flagged), web proxy / PAC (PAC over http = suspicious), DNS servers of connected adapters (router and well-known providers fine, unknown public servers "check this"), user-added trusted root certificates (HKCU physical store, subject + thumbprint). Query-only script; hosts file read on every OS
- DONE E3 Browser extensions audit (Chrome, Edge, Brave, Vivaldi, Opera, Chromium, Firefox; read-only): what each extension may do (all sites, web traffic, cookies, history, clipboard, native programs, debugger, proxy…) and how it got there (store / folder or command line / another program / policy / unsigned). "Needs attention" = installed outside the store, unsigned or debugger — broad permissions alone are "broad access", not a verdict; removal steps per browser. Tested with fixture profiles (Chromium, Opera single profile, Firefox) and in the E2E
- TODO E4 Downloads watcher (opt-in, static analysis only)
- TODO E5 Hayabusa event-log hunting (bundled)
- TODO E6 pe-sieve / HollowsHunter memory scan (bundled)

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
- Downloads folder watcher, browser-extension audit → Phase E; File Integrity Monitoring TODO
- MITRE ATT&CK mapping, IOC export (CSV/JSON/STIX 2.1), portable mode → Phase F; Sigma → Hayabusa (E5)
- DONE Windows CI (.github/workflows/ci.yml, windows-latest + ubuntu): unit tests incl. tests/windows-integration.test.ts (real PowerShell, Defender EICAR scan, Authenticode, forensics, network), full UI E2E, NSIS installer build + packaged smoke test — all green on Windows (run 3); the first runs found and fixed 2 real bugs (USB history without USBSTOR, PSModulePath breaking Authenticode)

## BLOCKED
- (none)
