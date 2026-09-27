# Development

## Requirements
- Node.js 20+ (22 LTS recommended) and npm
- Windows 10/11 x64 for Windows-specific modules (the app also runs on Linux/macOS with those modules reported as unavailable)

## Commands

| Command | What it does |
|---|---|
| `npm ci` | Install locked dependencies |
| `npm run dev` | Vite dev server (hot reload) + Electron |
| `npm run build` | Build main, preload and renderer into `dist/` |
| `npm start` | Build and launch |
| `npm run typecheck` | TypeScript strict check |
| `npm test` | Unit tests (vitest) |
| `npm run check:locales` | Arabic/English key + placeholder parity |
| `npm run check` | All of the above checks |
| `node scripts/ui-smoke.mjs <file.exe>` | End-to-end test on the real app + screenshots (Linux: prefix `xvfb-run -a`) |
| `npm run dist:win` | Build + Windows NSIS installer into `release/` (run on Windows) |
| `npm run dist:dir` | Build + unpacked app for the current OS (`release/*-unpacked`) |
| `node scripts/package-smoke.mjs [exe]` | Smoke-test a packaged build (Linux: prefix `xvfb-run -a`) |
| `npm run make:icon` | Regenerate `build/icon.ico` / `build/icon.png` from `build/icon.svg` |

On Windows you can also use `.\Start-Blazma.ps1` (`-Install`, `-Dev`, `-SkipBuild`).

## Tests
- `npx vitest run` — unit tests (166 pass; 5 real-engine YARA tests are skipped unless
  `BLAZMA_TEST_YR=/path/to/yr` is set, then 171 pass).
- `xvfb-run -a node scripts/ui-smoke.mjs <sample.exe>` — drives the real Electron app through every
  module in Arabic and English and refreshes `docs/screenshots/`. Optional: `BLAZMA_TEST_YR` (YARA-X
  + quarantine flow) and `BLAZMA_TEST_ZIP` (a ZipCrypto archive for the password-recovery flow).
- Network tests use mocks/localhost only.

## Continuous integration
`.github/workflows/ci.yml` runs on pushes to `main` / `claude/**`, pull requests and manual dispatch:
- **check** on `windows-latest` and `ubuntu-latest` — `npm run check`. On Windows this includes
  `tests/windows-integration.test.ts`, which runs the real PowerShell scripts (system facts,
  Defender/firewall status, forensics collectors, network), Authenticode (a signed system binary
  and an unsigned script with a hostile file name), and a report-only Defender scan of the EICAR
  test file (assembled at runtime). It only touches localhost, system files and temp files.
- **e2e** on Windows — the full UI smoke test on the real app; screenshots uploaded as an artifact.
- **package** on Windows — `npm run dist:win` + `scripts/package-smoke.mjs`; the unsigned installer
  is uploaded as an artifact (14 days). Nothing is published and no secrets are used.

## Packaging
Configuration: `electron-builder.yml`.
- Only `dist/` and `package.json` are packaged (everything is bundled by esbuild/Vite, so all npm
  packages are devDependencies). Source maps are excluded.
- Windows: per-user NSIS installer, `requestedExecutionLevel: asInvoker`, no elevation, Arabic +
  English installer UI, app data kept on uninstall (clear it from the Privacy Center).
- Electron fuses: RunAsNode off, `NODE_OPTIONS` off, Node inspector arguments off, embedded asar
  integrity validation on, only load the app from `app.asar`. Because the inspector is disabled,
  Playwright's `electron.launch()` can't attach to a packaged build — `scripts/package-smoke.mjs`
  uses the Chromium DevTools protocol instead.
- No `publish` target and no auto-update.
- `npm run dist:win` must run on Windows; on Linux, `electron-builder --win --dir` works but the
  NSIS uninstaller step needs Wine. CI builds it on Windows; install/uninstall is not yet tested.
- Code signing: set `CSC_LINK` / `CSC_KEY_PASSWORD` (or `WIN_CSC_*`) in the environment. Never
  commit certificates or passwords.
- `npm run make:icon` uses Playwright's Chromium; set `CHROMIUM_PATH` to use an existing Chromium.

## Adding a module
1. Add backend logic in `src/core` (pure) and/or `src/main/services` (OS access).
2. Add typed methods to `BlazmaApi` in `src/shared/api.ts`, expose them in `src/preload/index.ts`,
   and register validated handlers in `src/main/ipc.ts`.
3. Add the page in `src/renderer/pages`, remove `planned` from its `nav.ts` entry.
4. Add every string to **both** `locales/en.json` and `locales/ar.json`.
5. Add tests. Update docs/ROADMAP.md and CLAUDE.md status.

## Environment variables (development only)
- `BLAZMA_DATA_DIR` — use an isolated data directory
- `BLAZMA_FORCE_OFFLINE=1` — force Offline Mode on
