# Security Policy

BLAZMA CYBER is security-sensitive software. This document describes how the application
protects itself and its users, and how to report vulnerabilities.

## Reporting a vulnerability
Please open a private security advisory on the repository (GitHub → Security → Advisories) rather
than a public issue. Include steps to reproduce and affected version. Do not include real
malware samples or third-party data in reports.

## Design principles
- **Least privilege** — runs as a normal user. Administrator rights will only ever be requested for
  a specific function, with an explanation. No current feature requires elevation.
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
