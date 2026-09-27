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
- TODO Security Center: Defender quick/full/file/folder scans (MpCmdRun), threat history
- TODO YARA-X integration, rule manager, rule packs, custom rules
- TODO Quarantine (move + ACL lock + metadata + restore/delete/rescan)
- TODO Folder analysis

## Phase 3 — Intelligence
- TODO IP Intelligence (RDAP, reverse DNS, optional geolocation/reputation adapters, "approximate" notice)
- TODO Domain Intelligence (DNS records, RDAP, TLS certificate, infrastructure)
- TODO Reputation adapters (VirusTotal, AbuseIPDB, Shodan, Censys) with hash-first policy

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

## BLOCKED
- (none)
