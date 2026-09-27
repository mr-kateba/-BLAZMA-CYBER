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
│  ─ system-info                  ─ PowerShell runner          ─ settings.json  │
│  ─ windows-security             ─ (Defender, YARA-X,         ─ activity.json  │
│  ─ file-analysis                   hashcat… planned)         ─ network-activity│
│  ─ history / logger / secrets                                ─ logs/*.jsonl   │
│                                                              ─ secrets (DPAPI)│
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
  `object-src 'none'`, `frame-ancestors 'none'`.
- Navigation to anything other than the app bundle is blocked; `window.open` denied (https links
  open in the system browser); `<webview>` blocked.
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

Current scripts (read-only): OS caption/version/build, CPU cores, process count,
`Get-MpComputerStatus`, `Get-NetFirewallProfile`, `Get-AuthenticodeSignature`.

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
| `logs/blazma.log.jsonl` | structured redacted logs, rotated at 5 MB |
| `temp/` | temporary files (clearable) |

Writes are atomic (temp file + rename). Corrupt JSON is set aside, never crashes the app.

## 8. Planned engine integrations

| Capability | Engine | Integration | License | Notes |
|---|---|---|---|---|
| AV scanning | Microsoft Defender | `MpCmdRun.exe -Scan` + `Get-MpThreatDetection` via execFile/fixed scripts | OS component | Detect availability; passive mode when third-party AV is active |
| YARA | **YARA-X** (VirusTotal) | CLI (`yr`) adapter or `yara-x` Node/C bindings | BSD-3-Clause | Successor to libyara; memory-safe |
| Password recovery | hashcat | Separately installed executable, verified path + hash, execFile args | MIT | GPU; progress via `--status-json` |
| Password recovery | John the Ripper (jumbo) | Separately installed executable; `*2john` extractors | GPL-2.0 (core) + mixed | Never bundled/linked → no license contamination |
| Archive handling | 7-Zip | Separately installed `7z.exe` | LGPL-2.1 + unRAR restriction | For safe listing/extraction in quarantine/analysis |
| DNS | Node `dns` (`Resolver`) | built-in | — | Through NetworkGate when querying external resolvers |
| RDAP | IANA bootstrap + registry RDAP (HTTPS) | built-in fetch via NetworkGate | public data | Replaces port-43 WHOIS |
| TLS | Node `tls.connect` + `getPeerCertificate` | built-in | — | Through NetworkGate |
| Reputation | VirusTotal, AbuseIPDB, Shodan, Censys | HTTPS adapters via NetworkGate, user's own keys | service ToS | Hash lookup before any upload; upload needs explicit confirmation |
| Reports (later PDF) | Electron `printToPDF` | built-in | — | HTML report → PDF without extra deps |

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
