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

| Feature | Service | Data sent | Key needed |
|---|---|---|---|
| Dashboard → "Check public IP" | api.ipify.org | Nothing but the connection (your IP is visible to the service) | No |
| IP Intelligence → Reverse DNS | Your configured DNS resolver | The queried IP address | No |
| IP Intelligence → RDAP | data.iana.org (bootstrap) + the responsible regional registry (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC) | The queried IP address | No |
| IP / Domain Intelligence → ASN | Team Cymru, via DNS (`*.origin.asn.cymru.com`) through your resolver | The queried IP address | No |
| IP Intelligence → Approximate location | ipinfo.io | The queried IP address | Optional token |
| IP Intelligence → Tor check | check.torproject.org (downloads the public exit list; the queried IP is **not** sent) | Nothing identifying | No |
| Domain Intelligence → DNS records | Your configured DNS resolver | The queried domain | No |
| Domain Intelligence → RDAP | data.iana.org (bootstrap) + the TLD registry's RDAP server | The queried domain | No |
| Domain Intelligence → TLS certificate | The queried domain itself (port 443, handshake only) | A TLS handshake (SNI = the domain) | No |
| Reputation (IP/domain/hash) | VirusTotal, AbuseIPDB, Shodan | The queried IP, domain or **file hash** | Yes (yours) |
| File Analyzer → "Check SHA-256 on VirusTotal" | VirusTotal | The file's SHA-256 hash only | Yes (yours) |

Private, loopback and reserved IP addresses are **never** sent to external services (only your own
resolver may be asked for reverse DNS). Files are **never uploaded**: reputation uses hashes only.
File upload is not implemented; if it is ever added it will require explicit confirmation.

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
