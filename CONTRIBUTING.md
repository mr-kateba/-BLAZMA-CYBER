# Contributing to BLAZMA CYBER

Thank you for helping build a privacy-first, bilingual security workbench.

## Before you start
Read **CLAUDE.md** (engineering rules) and **docs/ARCHITECTURE.md**. The most important rules:

1. Never display fabricated data. If a value is unavailable, say so and why.
2. No button may appear functional unless it works.
3. Every user-visible string goes in **both** `locales/en.json` and `locales/ar.json`.
4. Use CSS logical properties; wrap technical values in `<Ltr>`.
5. No shell strings built from input. External requests only through `NetworkGate`.
6. Never log secrets, recovered passwords or file contents.

## Workflow
```bash
npm ci
npm run dev        # develop
npm run check      # typecheck + tests + locale parity (must pass)
```
Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).

## Tests
- Add unit tests for validation, parsing and anything security-relevant.
- Network tests must use mocks or localhost — never random public targets.
- For UI changes, run `node scripts/ui-smoke.mjs` (Linux: `xvfb-run -a …`) and check both languages.

## Dependencies
Justify every new dependency: license, maintenance, security, size. Record it in
`THIRD-PARTY-NOTICES.md`. Prefer a small, tested in-house implementation for simple functions.

## Scope
Contributions must be defensive or for authorized use (own files/systems/networks). Features that
target third-party accounts or services, evade security controls, or weaken Windows protections
will not be accepted.

## License of contributions
BLAZMA CYBER is licensed under GPL-3.0-or-later. By submitting a contribution you agree that it is
licensed under the same terms. Only add dependencies whose licenses are GPL-3.0-compatible.
