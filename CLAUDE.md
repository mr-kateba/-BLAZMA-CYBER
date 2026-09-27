# CLAUDE.md — Blazma Cyber engineering guide

Persistent guide for anyone (human or AI) working in this repository. Read it before changing code.
Update it whenever an architectural decision changes.

## Product vision

Blazma Cyber (Security • Forensics • Intelligence) is a **privacy-first, local-first, bilingual
(Arabic/English) Windows cybersecurity workbench**. It combines defensive security, static file
analysis, forensics, network diagnostics, intelligence and authorized password recovery in one
desktop GUI. It integrates mature engines (Microsoft Defender, YARA-X, …) through adapters instead
of re-implementing them. No account, no activation, no telemetry.

## Non-negotiable rules

1. **Never fabricate results.** Every value shown comes from a real function. When something can't
   be determined, show *unavailable* with the reason. Never show placeholder numbers.
2. **No fake buttons.** A control must work, or be visibly disabled/labeled as planned.
   Planned modules use `PlannedModule` (no action buttons).
3. **No hard-coded UI strings.** All text lives in `locales/en.json` + `locales/ar.json`.
   `npm run check:locales` and `tests/i18n.test.ts` enforce key and placeholder parity.
4. **RTL correctness.** Use CSS logical properties (`margin-inline-start`, `inset-inline-end`,
   `padding-inline`, `border-inline-start`…). Technical values (IP, hash, path, URL, command output)
   are wrapped in `<Ltr>` so they stay left-to-right inside Arabic text.
5. **No shell strings from input.** Subprocesses use `execFile` with argument arrays. PowerShell
   scripts are constants; user data reaches them only via `BLAZMA_ARG_*` environment variables
   (`runPowerShellJson(script, { args })`). Scripts must not contain `"` (tested).
6. **All external network access goes through `NetworkGate`** (`src/core/network-gate.ts`):
   blocked in Offline Mode, HTTPS only, no redirects, timeout, and logged to Network Activity
   (host + data category only). The renderer has no network access (CSP `connect-src 'self'`).
7. **Never log secrets.** Use `logger.*` (auto-redacts keys/tokens/passwords). Never log recovered
   passwords, API keys or file contents.
8. **Never execute analyzed files.** Static analysis reads bytes only.
9. **Least privilege.** The app runs unelevated. Elevation must be requested per-function with an
   explanation (only user today: Hayabusa live event-log scan via Start-Process -Verb RunAs after an in-app confirmation).
10. **Never weaken Windows security.** No disabling Defender, no firewall changes, no silent installs.
11. **The renderer is untrusted.** Every IPC argument is re-validated in `src/main/ipc.ts`.

## Architecture (summary — see docs/ARCHITECTURE.md)

```
Renderer (React, sandboxed, CSP)  ──window.blazma──▶  Preload (contextBridge, typed)
        ▲                                                   │ ipcRenderer.invoke
        │ progress events                                   ▼
Main process (Node) ── src/main/ipc.ts (validation, trusted-sender check, Result<T>)
   ├── services/file-analysis.ts   streaming hashes + static analysis (src/core/*)
   ├── services/system-info.ts     OS/CPU/RAM/disk/adapters (Node APIs)
   ├── services/windows-security.ts Defender/firewall/signature via fixed PowerShell scripts
   ├── services/powershell.ts      safe PowerShell runner (absolute path, -NoProfile, timeout)
   ├── services/settings|secrets|history|logger  local JSON state, DPAPI secrets, JSONL logs
   └── core/network-gate.ts         the only way out to the internet
```

`src/core/` is pure, platform-neutral TypeScript (validation, hashing ID, PE parser, entropy,
IOC extraction, detection model, i18n, redaction). It is the most heavily tested layer.

## Directory structure

```
Start-Blazma.ps1         PowerShell launcher (checks prerequisites, never installs silently)
locales/                 en.json, ar.json — ALL user-visible text
src/core/                pure logic (no Electron), unit-tested
src/shared/api.ts        typed IPC contract (BlazmaApi, Settings, result types)
src/main/                Electron main process + services
src/preload/             sandboxed bridge (bundled to a single CJS file)
src/renderer/            React UI: components/ (design system), pages/, nav.ts, styles/theme.css
tests/                   vitest unit tests
scripts/                 build-main, dev, check-locales, ui-smoke (E2E on real Electron)
docs/                    ARCHITECTURE, ROADMAP, DEVELOPMENT, screenshots/
```

## Coding conventions

- TypeScript strict (`noUncheckedIndexedAccess` on). No `any` in core; minimal in UI glue.
- IPC handlers return `Result<T>` (`{ ok, data } | { ok:false, error }`). `error` is an i18n code
  under `errors.*` — add it to both locale files.
- Long operations: stream data, accept an `AbortSignal`, emit progress (`files:progress`), and
  expose cancel. Never read whole large files into memory (analysis window is 32 MB; hashing streams).
- Components: reuse `src/renderer/components/ui.tsx` (Card, Badge, Gauge, DataTable, FileDrop,
  Notice, EmptyState, ErrorState, Skeleton, Toggle, Tabs, Ltr). Don't invent one-off styles.
- Every module must degrade gracefully: missing engine / non-Windows / access denied → clear state.

## Localization

- Arabic is first-class, not a translation afterthought. Write both strings when adding a key.
- Arabic uses Latin digits (`ar-u-nu-latn`) for readability of technical values.
- Direction is set on `<html dir>` by `I18nProvider`; never set `dir` ad hoc except via `<Ltr>`.

## Security / privacy

See SECURITY.md and PRIVACY.md. Defaults: **Offline Mode ON** on first launch; history on;
API keys only via Electron `safeStorage` (DPAPI) — refuse to store if encryption is unavailable.

## Testing rules

- `npm run check` = typecheck + unit tests + locale parity. Must pass before committing.
- `xvfb-run -a node scripts/ui-smoke.mjs <sample.exe>` runs the real app end-to-end (Linux) and
  refreshes `docs/screenshots/`. Set `BLAZMA_TEST_YR=/path/to/yr` to also run the YARA-X +
  quarantine flow and the real-engine tests in `tests/yara.test.ts`.
- CI (`.github/workflows/ci.yml`) runs the checks on real Windows, including
  `tests/windows-integration.test.ts` (real PowerShell/Defender/Authenticode), the UI E2E and the installer build.
- Never commit the EICAR test string contiguously: assemble it at runtime from two halves
  (antivirus would otherwise flag the repository/app itself).
- Network tests use mocks/localhost only. Never test against random public targets.

## Dependency rules

- Check license, maintenance and security before adding anything; record it in
  THIRD-PARTY-NOTICES.md. Prefer the standard library for small functions.
- External engines are **separate executables**. YARA-X (BSD-3), capa (Apache-2.0) and Detect It Easy
  (MIT) are bundled in the Windows installer: fetched at BUILD time only by scripts/fetch-engines.mjs
  and verified against SHA-256 pinned in engines.lock.json (update the lock via the "Engines inventory"
  workflow). John/hashcat remain user-installed. The app never auto-downloads or auto-executes binaries.
- ReversingLabs YARA rules (MIT) are vendored in engines/rules/ (pinned commit, compiled and
  false-positive-checked with YARA-X); they install as a read-only "pack" (can be disabled, not deleted).

## Current implementation status (keep in sync with docs/ROADMAP.md)

- DONE: project foundation, hardened Electron shell, design system, bilingual i18n + RTL/LTR,
  first-launch language picker, dashboard (real local data; Windows data via PowerShell),
  settings, structured redacted logging, secure API-key storage, Offline Mode + Network Activity,
  clear-data controls, File Analyzer (static: hashes, type, PE, entropy, IOCs, strings, signature
  on Windows, combined assessment), Hash Lab (text/file/verify/identify/compare), launcher,
  Quarantine (neutralized, verified restore), YARA-X adapter + rule manager (tested with real yr 1.20.0),
  Security Center (Defender scans/history/quarantine UI),
  IP / Domain Intelligence + Reputation Center (RDAP, DNS, Team Cymru ASN, TLS, ipinfo, Tor,
  VirusTotal/AbuseIPDB/Shodan), hash-only file reputation, Windows Forensics (read-only collectors,
  Linux /proc fallbacks), Network Toolkit (ping/trace/DNS/ports/routes/ARP/discovery with
  authorization confirmation), Password Recovery (encrypted-file detection + bring-your-own
  John/hashcat engine, authorization required, results never logged), Cases (evidence/notes/timeline),
  Reports (escaped HTML with strict CSP, JSON, PDF via offline printToPDF), Threat Hunting
  (cross-module correlation + persistence review), OSINT workspace (CT, Wayback, GitHub, mail-domain DNS,
  gated pivot links, provenance on every source).
  Phases A–D (docs/ROADMAP.md): simple mode + explanations, Device Security Score, bundled engines
  (YARA-X, capa, DIE, ReversingLabs rules), "Check an email" (local phishing analysis),
  "Was my password leaked?" (HIBP k-anonymity), abuse.ch reputation (MalwareBazaar/URLhaus/ThreatFox).
  Phase E: system proxy, signs of tampering, browser extensions audit, Downloads watcher,
  Hayabusa event-log hunting, HollowsHunter memory scan.
- Latest audit: docs/AUDIT-REPORT.md (3 bugs found and fixed; weaknesses and proposed features listed).
- NOT YET: signed installer.
- Verified on Linux (Xvfb) locally and on real Windows (Server 2025, build 26100) in CI: PowerShell
  facts, Defender status + EICAR file scan, Authenticode, forensics, network, full UI E2E, NSIS build.
  Not yet verified: Windows 10/11 desktop specifics (title-bar overlay, launcher, installer
  install/uninstall), Defender quick/full scans, real John/hashcat runs.
- PowerShell children never inherit PSModulePath (pwsh's value breaks Windows PowerShell 5.1 modules).

## Important decisions

| Date | Decision | Why |
|------|----------|-----|
| 2026-09 | License: GPL-3.0-or-later | Sensitive security tool: modified redistributions must stay open source; no-warranty clause; compatible with the engines we bundle; qualifies for free OSS code signing |
| 2026-09 | Bundle YARA-X, capa, DIE + ReversingLabs rules; pin by GitHub asset SHA-256 | Everyday users shouldn't install engines; pinned hashes keep the supply chain verifiable |
| 2026-09 | capa/DIE findings are weak evidence (capa ≥4 risky groups = strong); RL family rules are definitive, RL PUA is strong | Capabilities and packers also appear in legitimate software |
| 2026-09 | Electron + React + TypeScript | Best RTL/Arabic rendering, rich UI, testable on any OS; hardened (sandbox, contextIsolation, CSP). Alternatives in docs/ARCHITECTURE.md |
| 2026-09 | Custom tiny i18n instead of i18next | ~60 lines, fully tested, no dependency |
| 2026-09 | Offline Mode default ON | Privacy-first; user opts in to online lookups |
| 2026-09 | PowerShell via `-Command` + env-var args | No `-EncodedCommand`/`-ExecutionPolicy Bypass` (both are classic attacker IOCs our own threat hunting should flag) |
| 2026-09 | Windows facts: single in-flight PowerShell, failures cached 5 min, dashboard never waits on PowerShell | Audit found a PowerShell process storm on slow/failed queries |
| 2026-09 | YARA-X via official `yr` CLI (user-installed) | Maintained successor by VirusTotal, BSD-3; CLI keeps a process boundary and needs no native Node addon |
| 2026-09 | YARA runs from the rules dir with relative `ns:file.yar` args | YARA-X uses `:` as namespace separator, which clashes with Windows drive letters |
| 2026-09 | Quarantine stores XOR-0xFF neutralized blobs, restore verifies SHA-256 | Prevents accidental execution/AV re-detection; guarantees byte-exact restore |
| 2026-09 | NetworkGate.run() also covers DNS and TLS | DNS queries and TLS handshakes disclose the queried indicator too; Offline Mode must block them |
| 2026-09 | Private/reserved IPs never go to external sources | Privacy; geolocating RFC1918 space is meaningless |
| 2026-09 | 401/403 = "invalid key" only when a key was sent | Avoids blaming the user's key for network/policy blocks |
| 2026-09 | Forensics scripts are query-only (tested against a deny-list of state-changing cmdlets) | Forensics must never alter the evidence |
| 2026-09 | Locale-independent sources: CIM/Get-* objects, SIDs (S-1-5-32-544), Test-Connection | ping.exe/tracert/group names are localized on Arabic Windows |
| 2026-09 | Port check / discovery need an explicit authorization checkbox; discovery limited to attached private /24 | Authorized-use only; prevents accidental scanning of others |
| 2026-09 | Password recovery = orchestration only; engine is user-installed John/hashcat | Spec: don't reimplement cracking engines; keeps Blazma auditable and license-clean |
| 2026-09 | Recovered secrets reach the UI once, never logs/history | Secrets must not persist on disk |
| 2026-09 | Reports: every value HTML-escaped, no scripts, `default-src 'none'` CSP; PDF rendered in a hidden sandboxed window with JavaScript disabled | Evidence strings come from malware/untrusted sources; a report must never become an attack vector |
| 2026-09 | OSINT pivot links are re-derived in main from (type, value, id); the renderer never passes a URL to open | A compromised renderer must not be able to open arbitrary URLs/protocols via shell.openExternal |
| 2026-09 | Email OSINT queries only the domain's DNS; no mailbox probing (SMTP VRFY/RCPT) | Probing mail servers is intrusive and unreliable; privacy-first |
| 2026-09 | No in-app terminal: "Terminal" opens Windows Terminal / PowerShell in its own window (absolute path, clean env, unelevated) | A hosted terminal would need a native pty addon and would break the rule that the GUI never runs commands from user input |
| 2026-09 | Password leak check = HIBP k-anonymity range API only (5-char SHA-1 prefix, Add-Padding); no local strength "score", only concrete observations | The password must never leave the machine; a made-up score would be a fabricated result |
| 2026-09 | abuse.ch: one `abusech` key for 3 services (`REPUTATION_KEY` map); exact-hash listings weigh MalwareBazaar=malicious, ThreatFox ≥75 confidence=malicious else strong, URLhaus payload=strong; domains: active listing = red, historical = amber | Community-curated exact matches are strong evidence; historical abuse of a host is not proof it is dangerous now |
| 2026-09 | NetworkGate HTTP transport = Chromium net stack (in-memory session, credentials omitted); `redirect:'manual'` goes through `net.request` | Honours Windows proxy/PAC and certificate store like a browser; Electron's fetch cancels manual redirects |
| 2026-09 | Tamper checks are separate from the Device Security Score and never say "infected" | Ad-blockers, corporate proxies and debugging tools make similar changes; each finding shows its evidence and why it matters |
| 2026-09 | Extension "needs attention" = provenance (sideloaded/external/unsigned) or debugger; broad permissions alone = "broad access" | Ad-blockers and password managers legitimately need all-sites access; how an extension was installed is the stronger malware signal |
| 2026-09 | Hayabusa 4.1.0 bundled (AGPL-3.0 separate program + DRL-1.1 rules, source link in its LICENSE.txt); runs `dfir-timeline -t jsonl -p super-verbose` so each match keeps its rule author (DRL) | Sigma-based event-log hunting without extra tools; aggregation with a separate AGPL program is compatible with GPL-3.0 |
| 2026-09 | ATT&CK data is a generated compact table (scripts/make-attack-data.mjs) incl. MITRE's revoked-by map | Detection rules still use ids ATT&CK 19 replaced (e.g. T1070.001 → T1685.005); 41 KB instead of the 54 MB bundle |
| 2026-09 | IOC CSV cells starting with = + - @ are prefixed with ' | Evidence comes from attackers; exported CSV must not execute formulas in a spreadsheet |
| 2026-09 | Portable mode = `portable.txt` marker next to the exe (added by scripts/make-portable.mjs to the zip), data in `Blazma-data`; userData redirected before the single-instance lock | One build for installer and zip; a portable copy never touches %APPDATA%; DPAPI-encrypted keys stay bound to the Windows account (stated in UI) |
| 2026-09 | Updates: manual check only, link to the release page built in main (never the API's URL); no auto-download/installer | The app never downloads or runs binaries by itself; a signed-installer auto-update can come later |
| 2026-09 | File/folder Defender scans use -DisableRemediation | Blazma reports; the user decides (quick/full follow Defender policy, stated in UI) |
| 2026-09 | Branding: product name "Blazma Cyber" (not all-caps); logo = Blazma family hexagon (#FFB300→#FF3D00 gradient) with a white shield + check (`branding/`, `build/icon.*` via scripts/make-icon.mjs); env vars stay `BLAZMA_*` | Consistent with the sibling apps (Blazma Get, Blazma Boost); env names are an internal contract |
