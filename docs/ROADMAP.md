# Roadmap

Status legend: **DONE** (works, connected, both languages, tested where practical) ·
**IN PROGRESS** · **TODO** · **BLOCKED**. Nothing is marked DONE unless it actually works.

## Phase 0 — Research — DONE
- DONE Repository inspection (empty repo, greenfield)
- DONE Stack evaluation → Electron + React + TypeScript (docs/ARCHITECTURE.md §2)
- DONE Engine/dependency research and license review (THIRD-PARTY-NOTICES.md, ARCHITECTURE §8)
- DONE Architecture and threat model

## Phase 1 — Foundation — DONE (pending Windows verification)
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
- IN PROGRESS Verify Windows-only paths on real Windows 10/11 (Defender/firewall/Authenticode PowerShell scripts, title-bar overlay, launcher)

## Phase 2 — Local security
- DONE File Analyzer (static): streaming MD5/SHA-1/SHA-256/SHA-512, magic-byte type, MIME, timestamps, entropy, PE headers/sections/imports/exports/packer hints, IOC extraction, interesting strings, progress + cancel
- DONE Combined detection model with reasons and "incomplete" handling
- IN PROGRESS Digital signature verification (implemented via Get-AuthenticodeSignature; needs Windows verification)
- DONE Hash Lab: text/file hashing, integrity verification, hash identification (ranked candidates), comparison
- DONE Quarantine: neutralized storage (XOR + .blazmaq + 0600), metadata, verified restore (SHA-256), restore-to, delete, rescan; tested end-to-end
- DONE YARA-X integration (official `yr` CLI adapter, tested against real YARA-X 1.20.0): engine detection/selection, rule manager, builtin starter pack, custom rules with `yr check` validation, local import, enable/disable, file & folder scans (recursive), results in File Analyzer and combined assessment
- IN PROGRESS Security Center: Defender quick/full/file/folder scans (MpCmdRun, report-only for file/folder), threat history, quarantine UI — implemented; Defender paths need verification on real Windows
- DONE Folder scanning (YARA-X; Defender folder scan on Windows)

## Phase 3 — Intelligence — DONE (with noted verification gaps)
- DONE IP Intelligence: scope classification, reverse DNS, RDAP (IANA bootstrap, gated redirects), ASN (Team Cymru via DNS), approximate geolocation (ipinfo.io), Tor exit check, reputation, per-source provenance; private IPs never leave the machine; "approximate location" notice
- DONE Domain Intelligence: DNS (A/AAAA/CNAME/MX/NS/TXT/CAA/SOA), SPF/DMARC, RDAP registration, TLS certificate (handshake only), hosting ASN; IDN/URL input normalization; young-domain warning
- DONE Reputation Center + adapters: VirusTotal (IP/domain/hash), AbuseIPDB, Shodan; hash-only file reputation in File Analyzer, folded into the assessment
- DONE All sources go through NetworkGate (HTTP, DNS, TLS) → Offline Mode + Network Activity
- Verification: DNS/ASN/TLS verified live; RDAP, ipinfo, Tor list and reputation APIs verified with fixtures/mocks only (HTTPS to those hosts is blocked in the build environment)
- TODO Censys adapter (API changed to Platform tokens; not implemented — a stored key is unused, stated in UI)
- TODO Use Electron `net.fetch` for system-proxy support (after verifying redirect: 'manual' semantics)

## Phase 4 — Forensics — DONE (Windows collectors need verification on real Windows)
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

## Phase 7 — Polish
- TODO Integrated PowerShell terminal (separate from GUI operations; needs a pty — listed in the UI as planned)
- DONE Packaging config (electron-builder.yml): per-user NSIS (asInvoker, no elevation, Arabic + English installer), asar, hardened Electron fuses (RunAsNode off, NODE_OPTIONS/inspect off, asar integrity, only-load-from-asar), no publish/auto-update; app icon generated from the logo SVG (scripts/make-icon.mjs)
- DONE Packaged-app smoke test (scripts/package-smoke.mjs via CDP) — verified on Linux; `electron-builder --win --dir` also succeeds on Linux
- IN PROGRESS Windows installer: `npm run dist:win` must run on Windows (the NSIS uninstaller step needs Wine elsewhere) — not yet built/verified
- TODO Code signing (certificate via CSC_LINK / CSC_KEY_PASSWORD env vars only; never committed)
- DONE Keyboard review: Escape closes dialogs (E2E-tested), dialogs labelled (aria-labelledby/-describedby), focus moves into dialogs, visible focus ring; full screen-reader audit still TODO
- DONE Final security review (see docs/AUDIT-REPORT.md §8): external links now gated + allowlisted, window.open fully denied, report paths contained, npm audit 0, no secrets in repo
- TODO Performance profiling; docs with screenshots from real Windows

## Proposed additions (from docs/AUDIT-REPORT.md §7) — TODO, not yet scheduled
- TODO Device Security Score (BitLocker, UAC, Secure Boot, TPM, SMBv1, RDP, updates) — read-only, Arabic explanations
- TODO Tamper checks: hosts file, proxy, DNS servers, untrusted root certificates
- TODO Phishing email (.eml) analyzer: SPF/DKIM/DMARC results, received chain, real link targets, attachments
- TODO Pwned Passwords check via k-anonymity (only 5 hash chars leave the machine)
- TODO "What does this mean?" educational explanations for every indicator
- TODO Downloads folder watcher, File Integrity Monitoring, browser-extension audit
- TODO MITRE ATT&CK mapping, Sigma via external engine, IOC export (CSV/JSON/STIX 2.1), portable mode
- TODO Windows CI job (GitHub Actions windows-latest) to verify PowerShell paths

## BLOCKED
- (none)
