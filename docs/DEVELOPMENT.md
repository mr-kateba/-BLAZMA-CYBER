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
| `node scripts/ui-smoke.mjs <file>` | End-to-end test on the real app + screenshots (Linux: prefix `xvfb-run -a`) |

On Windows you can also use `.\Start-Blazma.ps1` (`-Install`, `-Dev`, `-SkipBuild`).

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
