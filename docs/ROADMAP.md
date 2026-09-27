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

## Phase 4 — Forensics
- TODO Processes (path, user, signature, hash, connections), services, drivers, startup, scheduled tasks
- TODO Users/groups, installed software, event logs, PowerShell history, USB history
- TODO Network Toolkit (ping, DNS, traceroute, adapters, routes, ARP, connections, listening ports, authorized port checks)
- TODO Per-function elevation with explanation

## Phase 5 — Recovery
- TODO Password Recovery workspace (hashcat / John adapters, wordlist/mask/candidate modes, pause/resume/stop, never log results)
- TODO Hash Lab: wordlist management, authorized audit workflows

## Phase 6 — Investigation
- TODO Cases (CASE-YYYY-NNN), evidence vs. notes, timeline
- TODO Threat Hunting with cross-module correlation
- TODO OSINT workspace (lawful public sources, provenance on every result)
- TODO Reports (HTML/JSON, Arabic/English; PDF later)
- TODO Integrated PowerShell terminal (separate from GUI operations)

## Phase 7 — Polish
- TODO Packaging (electron-builder NSIS/MSIX), code signing
- TODO Accessibility audit, keyboard navigation review
- TODO Performance profiling, security review, docs with screenshots from Windows

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
