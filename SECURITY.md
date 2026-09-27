# Security Policy

BLAZMA CYBER is security-sensitive software. This document describes how the application
protects itself and its users, and how to report vulnerabilities.

## Reporting a vulnerability
Please open a private security advisory on the repository (GitHub → Security → Advisories) rather
than a public issue. Include steps to reproduce and affected version. Do not include real
malware samples or third-party data in reports.

## Design principles
- **Least privilege** — runs as a normal user. Administrator rights will only ever be requested for
  a specific function, with an explanation. Today exactly one feature does: scanning this computer's
  event logs with Hayabusa (Windows lets only administrators read them). BLAZMA explains why, then
  Windows shows its own UAC prompt; only that one engine run is elevated and it only reads the logs.
- **No execution of analyzed files** — analysis is static: files are read, never run or loaded.
- **No command injection** — no shell is ever used. Subprocesses use argument arrays. PowerShell
  scripts are fixed constants; user data is passed as environment variables and consumed with
  `-LiteralPath`. Tests enforce this.
- **Input validation** — IPs, domains, ports, paths (absolute, no NUL bytes, no `\\?\`/`\\.\`
  device namespaces) and all IPC arguments are validated in the main process.
- **Process isolation** — Electron renderer is sandboxed with context isolation, strict CSP, no
  Node access, no network access, blocked navigation and permissions.
- **Secrets** — API keys are encrypted with Windows DPAPI (Electron `safeStorage`). If encryption is
  unavailable, keys are not stored. Keys are never logged or shown after saving.
- **Logging** — structured, local, with automatic redaction of keys, tokens, passwords and
  authorization headers. Recovered passwords and file contents are never logged.
- **Network** — every external request passes one gate: HTTPS only, no redirects, timeouts,
  blocked in Offline Mode, recorded in Network Activity.
- **Quarantine** — quarantined files are moved into a protected folder, stored byte-neutralized with
  a non-executable extension and owner-only permissions, and restored only on explicit user action
  after a SHA-256 integrity check. Nothing is ever deleted automatically because of a heuristic.
- **External engines** — YARA-X and Microsoft Defender are invoked as separate processes by path with
  argument arrays. File and folder Defender scans are report-only (`-DisableRemediation`).
- **Password recovery** — for files the user owns or is authorized to recover. Requires an explicit
  authorization confirmation. BLAZMA runs a user-installed engine (John the Ripper / hashcat) with
  argument arrays; masks are charset-restricted and paths validated. Recovered passwords are shown
  once in the UI and never written to logs, history or disk. Nothing leaves the machine.
- **Reports** — evidence often contains attacker-controlled text (file names, domains, extracted
  strings). Every value in an HTML report is escaped, the document contains no scripts and carries a
  `default-src 'none'` CSP, so opening a report cannot load remote content or run code. PDFs are
  rendered from that HTML in a hidden, sandboxed window with JavaScript disabled.
- **Threat hunting** — searches only local data and read-only live views (processes, connections,
  services, startup entries). Persistence flags are review prompts, never verdicts or automatic actions.
- **OSINT** — public, unauthenticated sources only, started by the user. Pivot links are rebuilt in
  the main process from the validated target and a known link id (the renderer cannot supply a URL),
  are https-only, open only after confirmation, and are blocked in Offline Mode. Email lookups never
  contact mail servers.
- **Bundled engines (supply chain)** — YARA-X, capa and Detect It Easy are downloaded only when a
  release is built, from their official GitHub releases, and must match SHA-256 digests pinned in
  `engines.lock.json` (taken from GitHub's own asset digests); any mismatch fails the build. The app
  never downloads or updates executables. capa and DIE read files statically; they never run them.
- **Resource limits** — streaming I/O, 32 MB static-analysis window, capped IOC/string/import
  counts, subprocess timeouts and output caps.
- **Windows security controls are never weakened** — BLAZMA CYBER does not disable Defender,
  change firewall rules or modify security policy.
- **No downloaded code execution** — the app never downloads and runs binaries. External engines
  must be installed by the user and are invoked by verified path.

## Authorized use
Password recovery, network checks and similar capabilities are intended only for files, systems
and networks you own or are explicitly authorized to test. They are not designed for, and will
not be extended to, attacks on third-party accounts or services.
