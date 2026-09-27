# Privacy

Blazma Cyber is **local-first**. Your files, scans and investigations stay on your computer.

## What we never do
- No telemetry, analytics, crash reporting or "phone home".
- No account, login, license key or activation server.
- No automatic file uploads — ever.
- Scan results are never sent to any server operated by the Blazma Cyber project (there is none).

## Offline Mode (on by default)
When Offline Mode is on (**Local only**), every optional external request is refused *before*
a connection is opened. Local modules keep working. Turn it off in the Privacy Center to allow
lookups you start yourself.

## External requests
When Offline Mode is off, Blazma Cyber contacts external services **only when you start an action**
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
| Reputation (abuse.ch) | MalwareBazaar, URLhaus, ThreatFox | The queried IP, domain or **file hash** (MalwareBazaar: hashes only) | Yes (yours, free) |
| File Analyzer → "Check the hash with reputation services" | VirusTotal and/or abuse.ch (the services you have keys for) | The file's SHA-256 hash only | Yes (yours) |
| OSINT → Certificate Transparency | crt.sh | The queried domain | No |
| OSINT → Wayback Machine | archive.org | The queried domain or URL | No |
| OSINT → GitHub profile | api.github.com | The queried username | No |
| OSINT → Accounts with this username (only the groups you tick) | Each checked site (301 social networks; 338 other sites if ticked) — every one listed in Network Activity | The queried username only (no login, no cookies) | No |
| OSINT → Mail domain DNS | Your configured DNS resolver | Only the domain part of the email address | No |
| Settings → About → "Check for updates" (only when pressed) | api.github.com (this project's public release list) | Nothing but the request itself | No |
| Was my password leaked? | api.pwnedpasswords.com (Have I Been Pwned) | Only the **first 5 characters of the password's SHA-1 hash** (k-anonymity, with response padding). The password and the rest of the hash never leave the computer; nothing is logged or saved | No |
| OSINT → Pivot links (only when clicked, after confirmation) | The site you picked, in your browser | The target, as shown in the confirmation | No |

Web requests use your Windows proxy settings (like your browser), carry no cookies and are not
cached on disk. DNS lookups and TLS certificate checks connect directly.

Private, loopback and reserved IP addresses are **never** sent to external services (only your own
resolver may be asked for reverse DNS). Files are **never uploaded**: reputation uses hashes only.
File upload is not implemented; if it is ever added it will require explicit confirmation.

The optional **Downloads watcher** (off by default) is local only: it reads new files in your
Downloads folder while Blazma is open, never opens, moves, deletes or uploads them.

Cases, reports and threat-hunting searches are **local only**: they are stored under the app's
data folder, are never uploaded, and can be removed from the Privacy Center (clear data → cases / reports).

Every attempted external request (sent, blocked or failed) is recorded in **Privacy Center →
Network Activity** with the time, module, service, host and the *category* of data sent.
Queried values and API keys are not stored in that log.

## Local data
Stored in `%APPDATA%\Blazma Cyber\`: settings, recent activity, network activity log, redacted
logs, encrypted API keys. You can clear activity, network activity, logs and temporary files from
the Privacy Center (with confirmation), or open the folder directly. Activity history can be
disabled in Settings → Privacy.

## Third-party services
Optional services (VirusTotal, AbuseIPDB, Shodan, Censys) are governed by their own privacy
policies and terms. They are used only with your own API keys.
