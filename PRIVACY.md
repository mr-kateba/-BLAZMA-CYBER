# Privacy

BLAZMA CYBER is **local-first**. Your files, scans and investigations stay on your computer.

## What we never do
- No telemetry, analytics, crash reporting or "phone home".
- No account, login, license key or activation server.
- No automatic file uploads — ever.
- Scan results are never sent to any server operated by the BLAZMA CYBER project (there is none).

## Offline Mode (on by default)
When Offline Mode is on (**Local only**), every optional external request is refused *before*
a connection is opened. Local modules keep working. Turn it off in the Privacy Center to allow
lookups you start yourself.

## External requests
When Offline Mode is off, BLAZMA CYBER contacts external services **only when you start an action**
that needs them. Currently:

| Feature | Service | Data sent |
|---|---|---|
| Dashboard → "Check public IP" | api.ipify.org | Nothing but the connection (your IP is visible to the service) |

Planned intelligence modules (IP/domain intelligence, reputation) will be listed here as they are
added. For file reputation, a **hash lookup** is preferred; uploading a file will always require
explicit confirmation.

Every attempted external request (sent, blocked or failed) is recorded in **Privacy Center →
Network Activity** with the time, module, service, host and the *category* of data sent.
Queried values and API keys are not stored in that log.

## Local data
Stored in `%APPDATA%\BLAZMA CYBER\`: settings, recent activity, network activity log, redacted
logs, encrypted API keys. You can clear activity, network activity, logs and temporary files from
the Privacy Center (with confirmation), or open the folder directly. Activity history can be
disabled in Settings → Privacy.

## Third-party services
Optional services (VirusTotal, AbuseIPDB, Shodan, Censys) are governed by their own privacy
policies and terms. They are used only with your own API keys.
