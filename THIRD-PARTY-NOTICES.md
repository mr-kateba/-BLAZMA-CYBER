# Third-Party Notices

BLAZMA CYBER uses the following third-party components. Each was reviewed for license
compatibility, maintenance status, platform support and security implications before adoption.
Full license texts are available in each package under `node_modules/<package>/LICENSE`
and are included with distributed builds.

## Runtime components (shipped with the application)

| Component | Version | License | Use | Source |
|---|---|---|---|---|
| Electron (includes Chromium, Node.js) | 44.4.5 | MIT (Chromium: BSD-3-Clause and others, see `LICENSES.chromium.html`) | Desktop runtime | https://github.com/electron/electron |
| React / React DOM | 19.3.0 | MIT | UI library | https://github.com/facebook/react |
| lucide-react | 1.48.0 | ISC | Icons | https://github.com/lucide-icons/lucide |
| IBM Plex Sans Arabic (via @fontsource) | 5.3.0 | SIL Open Font License 1.1 | Arabic + Latin UI font, bundled locally (no web font requests) | https://github.com/IBM/plex |
| JetBrains Mono (via @fontsource) | 5.3.0 | SIL Open Font License 1.1 | Monospace font for hashes/paths | https://github.com/JetBrains/JetBrainsMono |

## Development-only components (not shipped)

| Component | Version | License | Use |
|---|---|---|---|
| TypeScript | 7.0.2 | Apache-2.0 | Type checking |
| Vite | 8.3.1 | MIT | Renderer bundler / dev server |
| @vitejs/plugin-react | 6.1.1 | MIT | React support for Vite |
| esbuild | 0.28.2 | MIT | Main/preload bundler |
| Vitest | 5.0.2 | MIT | Unit tests |
| Playwright | 1.63.0 | Apache-2.0 | End-to-end UI smoke test |
| @types/* | — | MIT | Type definitions |

## Operating-system components used (not redistributed)

| Component | Use |
|---|---|
| Windows PowerShell 5.1 | Read-only system queries (fixed scripts) |
| Microsoft Defender cmdlets (`Get-MpComputerStatus`) | Defender status |
| NetSecurity cmdlets (`Get-NetFirewallProfile`) | Firewall status |
| `Get-AuthenticodeSignature` | Digital signature verification |

## Evaluated for future integration (NOT yet included)

| Engine | License | Planned integration | Assessment |
|---|---|---|---|
| YARA-X (VirusTotal) | BSD-3-Clause | **Integrated**: adapter to the user-installed `yr` CLI (tested with 1.20.0). Not bundled. | Actively maintained successor of YARA, memory-safe (Rust). |
| YARA (libyara) | BSD-3-Clause | Fallback only | Mature, in maintenance mode; YARA-X recommended by its authors. |
| hashcat | MIT | **Integrated**: user-installed executable, invoked by verified path with argument arrays | Compatible license; GPU acceleration; JSON status output. |
| John the Ripper (jumbo) | GPL-2.0 core, mixed for contributions | **Integrated**: user-installed executable only (never linked or bundled) | Best format coverage via `*2john` extractors; separate-process use avoids license coupling. |
| 7-Zip | LGPL-2.1 (+ unRAR restriction, BSD parts) | User-installed `7z.exe` | Safe archive listing for analysis/quarantine. |
| Microsoft Defender (`MpCmdRun.exe`) | OS component | **Integrated**: execFile with argument arrays | Detect availability; report-only file/folder scans. |

Rejected: unmaintained npm "hash identifier" and "PE parser" packages (small, easily implemented
and fully tested in-house: `src/core/hash-id.ts`, `src/core/pe.ts`); i18next (unnecessary for
this project's needs; replaced by `src/core/i18n.ts`).

External web services (VirusTotal, AbuseIPDB, Shodan, Censys, api.ipify.org) are used only on
explicit user action and are subject to their own terms. No API keys are distributed.
