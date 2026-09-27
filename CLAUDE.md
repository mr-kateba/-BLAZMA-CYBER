# CLAUDE.md — BLAZMA CYBER engineering guide

Persistent guide for anyone (human or AI) working in this repository. Read it before changing code.
Update it whenever an architectural decision changes.

## Product vision

BLAZMA CYBER (Security • Forensics • Intelligence) is a **privacy-first, local-first, bilingual
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
   explanation (not implemented yet — no current feature needs it).
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
- Never commit the EICAR test string contiguously: assemble it at runtime from two halves
  (antivirus would otherwise flag the repository/app itself).
- Network tests use mocks/localhost only. Never test against random public targets.

## Dependency rules

- Check license, maintenance and security before adding anything; record it in
  THIRD-PARTY-NOTICES.md. Prefer the standard library for small functions.
- External engines (YARA-X, hashcat, John) are **adapters to separately installed/verified
  executables** unless the license allows bundling. Never auto-download or auto-execute binaries.

## Current implementation status (keep in sync with docs/ROADMAP.md)

- DONE: project foundation, hardened Electron shell, design system, bilingual i18n + RTL/LTR,
  first-launch language picker, dashboard (real local data; Windows data via PowerShell),
  settings, structured redacted logging, secure API-key storage, Offline Mode + Network Activity,
  clear-data controls, File Analyzer (static: hashes, type, PE, entropy, IOCs, strings, signature
  on Windows, combined assessment), Hash Lab (text/file/verify/identify/compare), launcher,
  Quarantine (neutralized, verified restore), YARA-X adapter + rule manager (tested with real yr 1.20.0),
  Security Center (Defender scans/history/quarantine UI; Defender needs Windows verification).
- Latest audit: docs/AUDIT-REPORT.md (3 bugs found and fixed; weaknesses and proposed features listed).
- NOT YET: intelligence lookups, forensics, network toolkit,
  password recovery, cases, reports, threat hunting, OSINT, terminal, packaging/installer.
- Verified on Linux (Xvfb) only in this environment. Windows-specific PowerShell paths
  (Defender/firewall/Authenticode) are implemented but **still need verification on real Windows**.

## Important decisions

| Date | Decision | Why |
|------|----------|-----|
| 2026-09 | Electron + React + TypeScript | Best RTL/Arabic rendering, rich UI, testable on any OS; hardened (sandbox, contextIsolation, CSP). Alternatives in docs/ARCHITECTURE.md |
| 2026-09 | Custom tiny i18n instead of i18next | ~60 lines, fully tested, no dependency |
| 2026-09 | Offline Mode default ON | Privacy-first; user opts in to online lookups |
| 2026-09 | PowerShell via `-Command` + env-var args | No `-EncodedCommand`/`-ExecutionPolicy Bypass` (both are classic attacker IOCs our own threat hunting should flag) |
| 2026-09 | Windows facts: single in-flight PowerShell, failures cached 5 min, dashboard never waits on PowerShell | Audit found a PowerShell process storm on slow/failed queries |
| 2026-09 | YARA-X via official `yr` CLI (user-installed) | Maintained successor by VirusTotal, BSD-3; CLI keeps a process boundary and needs no native Node addon |
| 2026-09 | YARA runs from the rules dir with relative `ns:file.yar` args | YARA-X uses `:` as namespace separator, which clashes with Windows drive letters |
| 2026-09 | Quarantine stores XOR-0xFF neutralized blobs, restore verifies SHA-256 | Prevents accidental execution/AV re-detection; guarantees byte-exact restore |
| 2026-09 | File/folder Defender scans use -DisableRemediation | Blazma reports; the user decides (quick/full follow Defender policy, stated in UI) |
