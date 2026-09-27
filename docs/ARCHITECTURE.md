# Architecture

## 1. Goals that drive the design

- A real **desktop GUI** for Windows 10/11 x64 (PowerShell is a backend integration, not the UI).
- **Arabic RTL as a first-class layout**, English LTR, switchable at runtime.
- **Local-first and private**: nothing leaves the machine unless the user starts it; Offline Mode
  blocks everything external.
- **Security-sensitive software**: least privilege, strict process isolation, no shell injection.
- **Modular**: each module works independently and degrades gracefully.

## 2. Technology evaluation

| Option | RTL/Arabic | Modern UI (charts, animation) | Windows integration | Security model | Testable here* | Verdict |
|---|---|---|---|---|---|---|
| **Electron + React + TS** | Excellent (Chromium bidi, CSS logical properties) | Excellent | Via Node `child_process` → PowerShell/Win32 tools | Good when hardened (sandbox, contextIsolation, CSP, IPC validation) | Yes | **Selected** |
| Tauri 2 (Rust + WebView2) | Excellent (web) | Excellent | Rust/Win32, good | Very good (smaller surface) | Partially (needs Rust toolchain, WebView2) | Strong alternative; revisit for size |
| WPF / .NET 8 | Good but per-control `FlowDirection` quirks | Good with effort (third-party charts) | Excellent (native) | Good | No (.NET not available, WPF is Windows-only) | Rejected for now |
| WinUI 3 | Good | Good | Excellent | Good | No | Rejected (tooling immaturity, Windows-only builds) |
| Qt / PySide6 | Good | Good | Good | Good | Yes | Rejected (LGPL obligations, heavier packaging, Python distribution) |

\* "Testable here": can be built and exercised end-to-end in CI containers (Linux + Xvfb).

**Decision:** Electron + React + TypeScript, bundled with Vite (renderer) and esbuild (main/preload).
Electron's larger attack surface is mitigated by the hardening in §4. Tauri remains the most
likely future migration target if bundle size becomes a priority; the `src/core` layer is pure
TypeScript and the IPC contract (`src/shared/api.ts`) is explicit, which keeps such a move feasible.

## 3. Layers

```
┌──────────────────────────── Renderer (untrusted) ────────────────────────────┐
│ React UI · design system · pages · I18nProvider (dir=rtl|ltr) · no Node, no net │
└───────────────▲──────────────────────────────────────────────┬───────────────┘
                │ progress events                              │ window.blazma.* (typed)
┌───────────────┴────────────── Preload (sandboxed) ───────────▼───────────────┐
│ contextBridge exposes exactly BlazmaApi; ipcRenderer never leaks              │
└───────────────▲──────────────────────────────────────────────┬───────────────┘
                │                                              │ ipcMain.handle
┌───────────────┴────────────── Main process (Node) ───────────▼───────────────┐
│ ipc.ts: trusted-sender check · argument validation · Result<T> · task/cancel  │
│                                                                               │
│  Services                       Engines/adapters             Local state      │
│  ─ system-info · windows-sec.   ─ PowerShell runner          ─ settings.json  │
│  ─ file-analysis · quarantine   ─ Defender (MpCmdRun)        ─ activity.json  │
│  ─ defender · yara              ─ YARA-X `yr` CLI            ─ network-activity│
│  ─ intel · osint · nettools     ─ John / hashcat (user's)    ─ quarantine/    │
│  ─ forensics · recovery         ─ Node dns / tls             ─ yara/ cases/   │
│  ─ cases · reports · hunt                                    ─ reports/ logs/ │
│  ─ history / logger / secrets                                ─ secrets (DPAPI)│
│  NetworkGate ── the ONLY path to the internet (Offline Mode, HTTPS, logging)   │
└───────────────────────────────────────────────────────────────────────────────┘
         src/core: pure logic shared by all layers (validation, PE, IOC, detection, i18n)
```

### Module independence

Each module is a main-process service plus a renderer page, communicating only through
`BlazmaApi`. A failing module returns a `Result` error code; it cannot crash the shell.

## 4. Electron hardening

- `contextIsolation: true`, `sandbox: true`, `nodeIntegration: false`, `webSecurity: true`.
- Strict CSP: `script-src 'self'`, `connect-src 'self'` (dev server websocket only in dev),
  `object-src 'none'`, `frame-src 'none'`. (`frame-ancestors` is not used: browsers ignore it in a
  `<meta>` CSP and log an error; framing the app is impossible anyway because navigation, window.open
  and `<webview>` are blocked.)
- Navigation to anything other than the app bundle is blocked; `window.open` is always denied;
  `<webview>` blocked. External pages open only through validated IPC (§10).
- All permission requests (camera, mic, geolocation, notifications…) denied.
- IPC: every handler checks that the sender is the main window loading the app's own URL, and
  validates each argument (types, lengths, enums, absolute paths without NUL/device namespaces).
- DevTools disabled in packaged builds. Application menu removed. Single-instance lock.

## 5. Windows integration

`services/powershell.ts` runs **fixed** scripts:

- `powershell.exe` from `%SystemRoot%\System32\WindowsPowerShell\v1.0\` (absolute path, no PATH
  lookup), `-NoLogo -NoProfile -NonInteractive -Command <script>`, `windowsHide`, 20–30 s timeout,
  16 MB output cap, JSON output only.
- User data (e.g. file paths) is passed via `BLAZMA_ARG_*` env vars and read with
  `$env:BLAZMA_ARG_PATH` + `-LiteralPath`. It is never part of the script text.
- We intentionally avoid `-EncodedCommand` and `-ExecutionPolicy Bypass`: both are common
  attacker indicators, and a security tool should not look like malware to EDRs or to its own
  threat-hunting module.

All PowerShell scripts are read-only (Defender scans run through `MpCmdRun.exe` by absolute path
with execFile argument arrays, not PowerShell). The scripts cover system facts, `Get-MpComputerStatus`, `Get-NetFirewallProfile`, `Get-AuthenticodeSignature`,
Defender threat history, and the forensics collectors (tested against a deny-list of
state-changing cmdlets). Locale-independent sources are preferred (CIM objects, SIDs,
`Test-Connection`) because tool output and group names are localized on Arabic Windows.

## 6. Detection model

`src/core/detection.ts` combines independent signals (`defender`, `yara`, `signature`, `entropy`,
`hash_reputation`, `static`) with weights (`clean`, `neutral`, `weak`, `strong`, `malicious`).

- One weak heuristic is never enough for *Suspicious* (needs a combined score ≥ 3).
- *Malicious* requires a definitive engine detection (Defender/YARA) or overwhelming evidence.
- If Defender, YARA or signature verification did not run, the result is flagged `incomplete`
  and a clean-looking file is reported as **Unknown**, never as clean.
- Every verdict carries translatable reasons.

## 7. Data & storage

All under `%APPDATA%\BLAZMA CYBER\` (Electron `userData`, overridable by `BLAZMA_DATA_DIR`):

| Path | Content |
|---|---|
| `state/settings.json` | validated settings (unknown keys dropped) |
| `state/activity.json` | recent activity (max 200, can be disabled/cleared) |
| `state/network-activity.json` | external request log (host + data category, max 1000) |
| `secrets/api-keys.json` | API keys encrypted with DPAPI via `safeStorage` |
| `quarantine/*.blazmaq` + `index.json` | neutralized (XOR 0xFF) quarantined files, owner-only permissions |
| `yara/` | built-in and user YARA rules + index |
| `cases/CASE-YYYY-NNN.json` | investigation cases (evidence, notes, timeline) |
| `reports/` + `index.json` | generated HTML / JSON / PDF reports |
| `logs/blazma.log.jsonl` | structured redacted logs, rotated at 5 MB |
| `temp/` | temporary files (clearable) |

Writes are atomic (temp file + rename). Corrupt JSON is set aside, never crashes the app.

## 8. Engine integrations

| Capability | Engine | Integration | License | Notes |
|---|---|---|---|---|
| AV scanning | Microsoft Defender | `MpCmdRun.exe -Scan` (file/folder with `-DisableRemediation`) + threat history via fixed scripts | OS component | Verified in Windows CI (file scan detects EICAR; history) |
| YARA | **YARA-X** (VirusTotal) | user-installed `yr` CLI, run from the rules dir with relative `ns:file.yar` args | BSD-3-Clause | Implemented; tested with yr 1.20.0 |
| Password recovery | hashcat | user-installed executable, execFile args | MIT | Implemented (orchestration only) |
| Password recovery | John the Ripper (jumbo) | user-installed executable | GPL-2.0 (core) + mixed | Implemented; never bundled/linked; `*2john` extraction inside BLAZMA still TODO |
| Archive handling | 7-Zip | Separately installed `7z.exe` | LGPL-2.1 + unRAR restriction | Not integrated (evaluated) |
| DNS | Node `dns` (`Resolver`) | built-in | — | Through NetworkGate when querying external resolvers |
| HTTP transport | Chromium network stack (`session.fetch` / `net.request`, in-memory `blazma-network` session) | Electron | — | Honours Windows proxy settings (PAC/WPAD) and certificate store; no cookies, no disk cache |
| RDAP | IANA bootstrap + registry RDAP (HTTPS) | via NetworkGate | public data | Replaces port-43 WHOIS |
| TLS | Node `tls.connect` + `getPeerCertificate` | built-in | — | Through NetworkGate |
| Reputation | VirusTotal, AbuseIPDB, Shodan, abuse.ch (MalwareBazaar, URLhaus, ThreatFox) | HTTPS adapters via NetworkGate, user's own keys (one abuse.ch Auth-Key for all three; POST APIs) | service ToS | Hash lookups only; file upload is not implemented. Censys not implemented |
| Leaked passwords | Have I Been Pwned — Pwned Passwords | k-anonymity range API via NetworkGate (5-char SHA-1 prefix, padding) | service ToS (no key) | Matching is local; the password is never logged |
| OSINT | crt.sh, Wayback availability API, GitHub REST API, mail-domain DNS | HTTPS/DNS via NetworkGate | service ToS / public data | Public, unauthenticated sources only |
| Reports | Electron `printToPDF` | built-in | — | HTML report → PDF in a hidden sandboxed window, JavaScript disabled |

## 9. Threat model (summary)

| Threat | Mitigation |
|---|---|
| Malicious file under analysis exploits the parser | Bounds-checked PE parser (fuzz-tested with random input), no execution, analysis window cap |
| Crafted filename/path injects commands | No shell; execFile arrays; PowerShell env-var args; path validation |
| Compromised renderer (XSS) escalates | sandbox + contextIsolation + CSP + typed preload + main-side validation + sender check |
| Secret leakage via logs | Structural redaction of keys/tokens/passwords + inline patterns; tested |
| Silent data exfiltration | Single NetworkGate, Offline Mode, Network Activity log, renderer has no network |
| Supply-chain | Minimal deps, lockfile, license review, no postinstall downloads beyond Electron's official binary |
| Privilege misuse | Runs unelevated; per-feature elevation with explanation (future) |
| Evidence text (file names, malware strings) turns a report into an attack | Every value HTML-escaped, no scripts, `default-src 'none'` CSP in the report |
| Compromised renderer opens arbitrary URLs/protocols | No `window.open`; `app:openLink` host allowlist; OSINT pivots re-derived in main |
| Tampered packaged app / binary reused as a Node runtime | Electron fuses + asar integrity validation (§11) |

## 10. Investigation and intelligence flows

- **Cases** (`services/cases.ts`): one JSON file per case; evidence (`kind`, `value`, `source`,
  `details`), notes and an automatic timeline. Pages add evidence through the shared `AddToCase`
  component.
- **Reports** (`core/report.ts` pure builder + `services/reports.ts`): HTML/JSON from a case in the
  chosen language; PDF via `printToPDF`. Open/remove only touch files inside `reports/`.
- **Threat Hunting** (`core/hunt.ts` + `services/hunt.ts`): types the query (IP/domain/hash/text),
  matches with token boundaries across local stores and live read-only collectors, and returns a
  hits timeline; persistence review flags autostart entries by location (prompts, not verdicts).
- **OSINT** (`core/osint.ts` + `services/osint.ts`): validated target → selected sources through
  `IntelService` helpers (NetworkGate, provenance URL + time per source). Pivot links:
  renderer sends `(type, value, pivotId)` → main re-normalizes the target, rebuilds the link list,
  picks the id, requires https, and opens it via `gate.run(...)` → `shell.openExternal` (blocked in
  Offline Mode, recorded in Network Activity). The renderer never supplies a URL.
- **External result links** (e.g. a VirusTotal page): `app:openLink(url)` accepts only https URLs
  to `EXTERNAL_LINK_HOSTS` (no credentials/ports), then goes through NetworkGate.

## 11. Packaging & hardening

`electron-builder.yml` packages only `dist/` + `package.json` into `app.asar` (all code is bundled).
Windows target: per-user NSIS, `asInvoker`, no elevation, Arabic + English installer, no publish or
auto-update. Fuses flipped at package time: RunAsNode off, `NODE_OPTIONS` off, Node CLI inspect
arguments off, embedded asar integrity validation on, only load app from asar. DevTools are
disabled when packaged. `scripts/package-smoke.mjs` verifies a packaged build over CDP (renderer
loads from asar, preload bridge present, no Node in the renderer). Verified on Linux and on Windows
in CI (installer built, packaged app smoke-tested); installing/uninstalling on a desktop is untested.
