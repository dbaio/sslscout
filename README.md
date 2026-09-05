# SSLScout

[![CI](https://github.com/dbaio/sslscout/actions/workflows/ci.yml/badge.svg)](https://github.com/dbaio/sslscout/actions/workflows/ci.yml)

SSLScout is a TLS certificate expiry monitor written in Go, using the standard
library only and with **zero external dependencies**. It reads a list of
domains, opens a TLS connection to each of them in parallel, writes the result
to `public/report.json` and fires alerts through Slack, Microsoft Teams and
e-mail (SMTP) when a certificate is close to expiring, has already expired or
could not be verified. A single-file static dashboard (`public/index.html`)
reads that JSON and shows the state of the fleet.

Both the dashboard and the alerts are translatable. They ship in English and
also come with Brazilian Portuguese — see [Languages](#languages-i18n).

---

## Table of contents

- [Dashboard](#dashboard)
- [Requirements](#requirements)
- [Install and build](#install-and-build)
- [Quick start](#quick-start)
- [Command-line flags](#command-line-flags)
- [Configuration file](#configuration-file-configjson)
- [Languages (i18n)](#languages-i18n)
- [Format of `domains.txt`](#format-of-domainstxt)
- [Format of `report.json`](#format-of-reportjson)
- [Serving the dashboard](#serving-the-dashboard)
- [Docker](#docker)
- [Scheduling](#scheduling)
- [Notifications](#notifications)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [License](#license)

---

## Dashboard

<!--
  Placeholder for the screenshot. To produce one:
    make serve            # brings the dashboard up on http://localhost:8080
  then save the image as docs/dashboard.png and replace the comment below with:
    ![SSLScout dashboard](docs/dashboard.png)
-->

_(screenshot pending — see the instructions in the comment in this file)_

The dashboard is a single file, `public/index.html`, with no CDN, no remote
fonts and no external request whatsoever: it works offline, and the only thing
it fetches is the `report.json` sitting next to it, by relative path. From that
JSON it renders the summary per state, one record per monitored domain and the
time the report was generated.

Because it is a static file, anything can serve it: the built-in `-serve` mode,
nginx, Apache, GitHub Pages or an object bucket.

---

## Requirements

- **Go 1.21 or newer** to build (that is the version declared in `go.mod`).
- No external dependencies: there is no `go.sum`, no vendoring, no third-party
  library.
- Outbound TCP to the ports of the monitored domains (usually 443).
- The system CA root certificates. On an ordinary Linux machine they are
  already installed; on minimal containers they have to be installed
  explicitly (see [Docker](#docker)).

You do not need Go installed to *run* the binary. For a fully static binary
(useful in `scratch`/`distroless` containers), build with `CGO_ENABLED=0` —
which is what the `Dockerfile` does.

---

## Install and build

```sh
git clone https://github.com/dbaio/sslscout.git
cd sslscout
go build ./cmd/sslscout
```

That produces the `sslscout` executable in the current directory.

Alternatively, through the Makefile — which injects the version (taken from
`git describe`) into the `main.version` variable, the same one the `-version`
flag prints:

```sh
make build                 # version derived from git
make build VERSION=1.0.0   # fixed version
```

Cross-compiling works normally, since there is no CGO:

```sh
GOOS=linux   GOARCH=amd64 go build -o sslscout-linux-amd64   ./cmd/sslscout
GOOS=freebsd GOARCH=amd64 go build -o sslscout-freebsd-amd64 ./cmd/sslscout
```

---

## Quick start

```sh
# 1. List the domains you want to monitor (one per line).
$EDITOR domains.txt

# 2. Create your configuration from the example.
cp config.example.json config.json
chmod 600 config.json
$EDITOR config.json

# 3. Run the check. This writes public/report.json.
go build ./cmd/sslscout
./sslscout

# 4. Open the dashboard.
./sslscout -serve :8080
# then browse to http://localhost:8080
```

If you just want to see the report once, with no notifications and no server:

```sh
./sslscout -notify=false -out /tmp/report.json
```

If you would rather run everything in containers, jump to
[Docker Compose](#docker-compose-checker--nginx).

---

## Command-line flags

```
sslscout [flags]
```

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `-domains` | string | `domains.txt` | File with the domain list. |
| `-config` | string | `config.json` | Configuration file. |
| `-out` | string | `public/report.json` | Path of the generated JSON report. |
| `-timeout` | duration | `10s` | Per-connection timeout (e.g. `5s`, `1m`). |
| `-concurrency` | int | `20` | Number of simultaneous checks. |
| `-retries` | int | `3` | Attempts per domain on transient failures. |
| `-threshold` | int | `15` | Overrides `alert_threshold_days`. Only takes effect when given explicitly. |
| `-critical` | int | `7` | Overrides `critical_threshold_days`. Only takes effect when given explicitly. |
| `-lang` | string | `en` | Language of the notifications: `en` or `pt-BR`. Overrides `language`. |
| `-notify` | bool | `true` | Sends notifications. Use `-notify=false` to turn them off. |
| `-serve` | string | (empty) | After checking, serves the report directory on this address (e.g. `:8080`). |
| `-interval` | duration | `0` | Re-runs the check on this interval. `0` runs once. |
| `-fail-on` | string | `none` | Exits non-zero if any result is at this level or worse: `none`, `warning`, `critical`, `invalid`, `error`. |
| `-quiet` | bool | `false` | Suppresses the informational output. |
| `-version` | bool | `false` | Prints the version and exits. |

Notes that matter:

- **Configuration precedence:** an explicit flag on the command line beats the
  environment variable, which beats the configuration file, which beats the
  built-in default.
- `-notify` is a boolean flag defaulting to `true`. Writing just `-notify` does
  not turn it off; to turn it off you need `-notify=false` (the standard Go
  boolean flag syntax).
- `-serve` serves the **directory containing** the `-out` file. With the
  defaults that is `public/`, i.e. `index.html` and `report.json` together.
  `report.json` is served with `Cache-Control: no-store` so the browser does
  not show a stale report.
- `-interval` pairs well with `-serve`: the process stays up serving the
  dashboard and re-running the check periodically, with no cron needed.
- `-fail-on` uses the same severity scale as the report states, so
  `-fail-on warning` also fails on `critical`, `expired`, `invalid` and
  `error`. It does not apply while the process stays up because of `-serve`.
- An **explicit** `-config` pointing at a nonexistent file is an error. A
  missing default `config.json` is not: in that case the built-in defaults plus
  the environment variables apply.
- `-lang` only changes the **notifications**. The terminal output is always in
  English — it is written for whoever is reading a log, not for whoever
  receives the alert.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Execution error: invalid configuration, missing file, failure to write the report, failure to bind the `-serve` port. |
| `2` | The `-fail-on` threshold was reached. |

Keeping those two apart matters in CI: `1` means "the tool could not run",
`2` means "it ran and found what you told it to look for".

---

## Configuration file (`config.json`)

The default path is `config.json` in the current directory, adjustable with
`-config`. Use `config.example.json` as the starting point. **The real file
must never be committed** — it holds the SMTP password and the webhook URLs,
which are secrets.

```json
{
  "alert_threshold_days": 15,
  "critical_threshold_days": 7,
  "timeout_seconds": 10,
  "concurrency": 20,
  "retries": 3,
  "language": "en",
  "slack_webhook_url": "",
  "teams_webhook_url": "",
  "smtp": {
    "enabled": false,
    "host": "smtp.example.com",
    "port": 587,
    "username": "your_username",
    "password": "your_password",
    "from": "alerts@example.com",
    "to": ["sre@example.com"],
    "tls": "starttls"
  }
}
```

### Top-level fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `alert_threshold_days` | int | `15` | Days remaining at or below which a certificate becomes `warning`. |
| `critical_threshold_days` | int | `7` | Days remaining at or below which a certificate becomes `critical`. Must be lower than `alert_threshold_days`. |
| `timeout_seconds` | int | `10` | Per-connection timeout, in seconds. Equivalent to `-timeout`. |
| `concurrency` | int | `20` | Simultaneous checks. Equivalent to `-concurrency`. |
| `retries` | int | `3` | Attempts per domain on transient failures. Equivalent to `-retries`. |
| `language` | string | `"en"` | Language of the notifications: `en` or `pt-BR`. Equivalent to `-lang`. |
| `slack_webhook_url` | string | `""` | Slack incoming webhook. Empty disables the channel. |
| `teams_webhook_url` | string | `""` | Microsoft Teams incoming webhook. Empty disables the channel. |
| `smtp` | object | — | E-mail configuration (below). |

### The `smtp` object

| Field | Type | Description |
| --- | --- | --- |
| `enabled` | bool | Turns e-mail delivery on or off. With `false` the rest of the object is ignored. |
| `host` | string | SMTP server. |
| `port` | int | SMTP port. Typically `587` for STARTTLS, `465` for implicit TLS, `25` for an internal relay without TLS. |
| `username` | string | Authentication user. Leave empty on relays that do not require authentication. |
| `password` | string | Authentication password. **Prefer the environment variable.** |
| `from` | string | Sender address. |
| `to` | array of string | Recipients. |
| `tls` | string | TLS mode: `starttls`, `implicit` or `none`. |

### `smtp.tls` modes

| Value | When to use it | How it works |
| --- | --- | --- |
| `starttls` | The default. Port 587. | Connects in the clear and upgrades to TLS with the `STARTTLS` command before authenticating. |
| `implicit` | Port 465 (SMTPS). | The connection starts inside TLS, with no `STARTTLS`. |
| `none` | A trusted internal relay, port 25. | No encryption. Only use it on a network you control — the password, if any, travels in the clear. |

### Environment variables

These variables **override** the corresponding value from the configuration
file. They are the recommended way to supply secrets, because they let you keep
a `config.json` with nothing sensitive inside:

| Variable | Overrides |
| --- | --- |
| `SSLSCOUT_SLACK_WEBHOOK_URL` | `slack_webhook_url` |
| `SSLSCOUT_TEAMS_WEBHOOK_URL` | `teams_webhook_url` |
| `SSLSCOUT_SMTP_USERNAME` | `smtp.username` |
| `SSLSCOUT_SMTP_PASSWORD` | `smtp.password` |
| `SSLSCOUT_LANG` | `language` |

Example:

```sh
export SSLSCOUT_SLACK_WEBHOOK_URL='https://hooks.slack.com/services/T000/B000/xxxx'
export SSLSCOUT_SMTP_PASSWORD='app-password'
./sslscout
```

---

## Languages (i18n)

Two things can be translated, and they are chosen independently:

| What | Who chooses | Where | Default |
| --- | --- | --- | --- |
| The **alerts** (Slack, Teams, e-mail) | whoever runs SSLScout | `language` in `config.json`, `SSLSCOUT_LANG`, or `-lang` | `en` |
| The **dashboard** | whoever opens the page in a browser | the picker in the header, remembered per browser | `en` |

Everything else — the terminal output, the flag help, the error messages, the
`report.json` field names and the CSV export header — is always in English.
Those are machine and operator surfaces; translating them would only make logs
harder to search and reports harder to diff.

Languages available today: **English (`en`)** and **Brazilian Portuguese
(`pt-BR`)**.

### Alerts

The default is English. To send them in Brazilian Portuguese, pick whichever
fits your setup:

```sh
# in config.json
{ "language": "pt-BR" }

# or in the environment (handy in systemd and Docker)
export SSLSCOUT_LANG=pt-BR

# or per run
./sslscout -lang pt-BR
```

An unsupported language is a configuration error, not a silent fallback:

```
sslscout: invalid configuration:
unsupported language "klingon" (use one of: en, pt-BR)
```

Region variants without a catalog of their own fall back to the closest base
language, so `pt-PT` uses the `pt-BR` catalog and `en-GB` uses `en`.

The language changes the wording, the plural forms and the date format:

```
en     expired.badssl.com:443 — expired 4164 days ago, on 2015-04-12
pt-BR  expired.badssl.com:443 — expirado há 4164 dias, em 12/04/2015
```

### Dashboard

The dashboard picks its language in this order, first match wins:

1. `?lang=pt-BR` in the URL — useful for a bookmark or a link in a runbook;
2. what the visitor last chose in the header picker (kept in `localStorage`,
   so it is per browser and never leaves the machine);
3. the deployment default, from `<html data-default-lang="…">` in
   `public/index.html` — shipped as `en`;
4. `en`.

Setting the deployment default to `auto` makes the page follow the browser's
`Accept-Language` instead, falling back to English when it has no catalog for
it:

```html
<html lang="en" data-theme="" data-default-lang="auto">
```

Dates, times and numbers follow the chosen language too (`Sep 5, 2026` versus
`5 de set. de 2026`, `4,164` versus `4.164`).

### Adding a language

Two independent places, both self-contained.

**Alerts** — `pkg/i18n/i18n.go`. Add a `Lang` constant and one entry to
`catalogs`; `Supported()`, the `-lang` help text and the validation error pick
it up automatically:

```go
const EsES Lang = "es-ES"

var catalogs = map[Lang]catalog{
    // …
    EsES: {
        subject: plural{
            one:   "SSLScout: %d certificado necesita atención",
            other: "SSLScout: %d certificados necesitan atención",
        },
        days:       plural{one: "%d día", other: "%d días"},
        dateFormat: "02/01/2006",
        // groupTitles, errorKinds and the line templates…
    },
}
```

`TestCatalogsAreComplete` in `pkg/i18n/i18n_test.go` fails if the new catalog
is missing any key the English one has, so a half-finished translation cannot
leak a raw token like `hostname_mismatch` into an alert.

**Dashboard** — `public/index.html`, the `LANGS` object at the top of the
script. Add an entry and its code to `LANG_ORDER`:

```js
var LANG_ORDER = ['en', 'pt-BR', 'es-ES'];

var LANGS = {
  // …
  'es-ES': {
    name: 'Español',      // shown in the picker, in its own language
    locale: 'es-ES',      // handed to Intl for dates and numbers
    s: { title: 'SSLScout — Monitor de Certificados', /* … */ }
  }
};
```

A string is plain text, a plural object `{one, other}`, or an array of segments
where `{code: "…"}` and `{strong: "…"}` become real elements. Placeholders look
like `{name}`. Any key you leave out falls back to English, so a partial
translation degrades one string at a time instead of breaking the page.

---

## Format of `domains.txt`

One entry per line. The rules are:

- `#` starts a comment — it can take the whole line or come after the entry, at
  the end of the line.
- Blank lines are ignored.
- Duplicates are dropped, preserving the original order of appearance.
- Three entry formats are accepted:
  1. `domain` — port 443 is assumed;
  2. `domain:port` — for TLS services outside 443;
  3. `https://domain/path` — the URL is accepted and only host and port are
     extracted; the path is discarded.

```
# SSLScout domain list

# 1) plain domain — port 443 implied
example.com
www.example.com

# 2) domain with an explicit port
mail.example.com:993        # IMAPS
ldap.example.com:636        # LDAPS
api.example.com:8443        # trailing comment

# 3) URL — only host and port are used, /status is ignored
https://panel.example.com/status
https://internal.example.com:9443/health
```

Every entry above is normalized to the `host:port` form in the report — that is
what shows up in the `domain` field.

---

## Format of `report.json`

The report is rewritten in full on every run, at the `-out` path (by default
`public/report.json`). The current schema is **version 2**.

```json
{
  "schema_version": 2,
  "generated_at": "2026-09-05T00:51:49.072652Z",
  "duration_ms": 833,
  "alert_threshold_days": 15,
  "critical_threshold_days": 7,
  "summary": {
    "total": 5,
    "ok": 2,
    "warning": 0,
    "critical": 0,
    "expired": 1,
    "invalid": 2,
    "error": 0
  },
  "results": [
    {
      "domain": "github.com:443",
      "host": "github.com",
      "port": 443,
      "status": "ok",
      "valid": true,
      "expires_at": "2026-11-29T23:59:59Z",
      "issued_at": "2026-09-01T00:00:00Z",
      "days_remaining": 85,
      "subject": "github.com",
      "issuer": "Sectigo Public Server Authentication CA DV E36",
      "serial_number": "a59ebdb596751db7f5c095079613953c",
      "dns_names": [
        "github.com",
        "www.github.com"
      ],
      "tls_version": "TLS 1.3",
      "cipher_suite": "TLS_AES_128_GCM_SHA256",
      "checked_at": "2026-09-05T00:51:48.239286Z",
      "duration_ms": 89,
      "attempts": 1
    },
    {
      "domain": "expired.badssl.com:443",
      "host": "expired.badssl.com",
      "port": 443,
      "status": "expired",
      "valid": false,
      "expires_at": "2015-04-12T23:59:59Z",
      "issued_at": "2015-04-09T00:00:00Z",
      "days_remaining": -4164,
      "subject": "*.badssl.com",
      "issuer": "COMODO RSA Domain Validation Secure Server CA",
      "serial_number": "4ae79549fa9abe3f100f17a478e16909",
      "dns_names": [
        "*.badssl.com",
        "badssl.com"
      ],
      "tls_version": "TLS 1.2",
      "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "metadata_insecure": true,
      "checked_at": "2026-09-05T00:51:48.239289Z",
      "duration_ms": 833,
      "attempts": 1,
      "error": "tls: failed to verify certificate: x509: certificate has expired or is not yet valid: \"*.badssl.com\" certificate is expired",
      "error_kind": "expired"
    }
  ]
}
```

This is a real excerpt from a five-domain run, with `results` cut down to two
items so it fits here — which is why the `summary` counts do not match what is
listed. The first item passed verification, the second did not. Notice that
`error` and `error_kind` **do not appear** on the healthy item, and that the
certificate fields of the broken one come with `metadata_insecure`.

### Envelope fields

| Field | Type | Description |
| --- | --- | --- |
| `schema_version` | int | Format version. Currently `2`. |
| `generated_at` | string (RFC 3339) | When the report was generated. |
| `duration_ms` | int | Total run duration, in milliseconds. |
| `alert_threshold_days` | int | The `warning` threshold used in this run. |
| `critical_threshold_days` | int | The `critical` threshold used in this run. |
| `summary` | object | Result counts per state, plus `total`. |
| `results` | array | One object per checked domain. |

### Fields of each `results` item

Always present:

| Field | Type | Description |
| --- | --- | --- |
| `domain` | string | The normalized entry, in `host:port` form. |
| `host` | string | Host name. |
| `port` | int | Port used for the connection. |
| `status` | string | One of `ok`, `warning`, `critical`, `expired`, `invalid`, `error`. |
| `valid` | bool | `true` only when `status` is `ok`, `warning` or `critical`. |
| `days_remaining` | int | Days until expiry. Can be negative when the certificate has already expired. Omitted or `0` when `status` is `error`. |
| `checked_at` | string (RFC 3339) | When this domain was checked. |
| `duration_ms` | int | Duration of this domain's check. |
| `attempts` | int | How many attempts were needed (see `-retries`). |

Optional (`omitempty` — they may not appear, typically when `status` is `error`
and there was no certificate to read):

| Field | Type | Description |
| --- | --- | --- |
| `expires_at` | string (RFC 3339) | `NotAfter` of the leaf certificate. |
| `issued_at` | string (RFC 3339) | `NotBefore` of the leaf certificate. |
| `subject` | string | Certificate subject (usually the CN). |
| `issuer` | string | Issuer. |
| `serial_number` | string | Serial number. |
| `dns_names` | array of string | DNS SANs of the certificate. |
| `tls_version` | string | Negotiated version, e.g. `TLS 1.3`. |
| `cipher_suite` | string | Negotiated cipher. |
| `metadata_insecure` | bool | `true` when the certificate fields above came from the diagnostic handshake, **without verification** (see below). Absent when the connection was verified successfully. |
| `error` | string | Readable error message. |
| `error_kind` | string | Error classification (table below). |

### `status` values

Evaluated in this order of precedence — the first one that applies wins:

| `status` | Meaning | `valid` |
| --- | --- | --- |
| `error` | Network, DNS, timeout or refused-connection failure, or the server presented no certificate at all. There is no certificate metadata to report. | `false` |
| `expired` | The certificate was read successfully, but its `NotAfter` has passed. `days_remaining` is negative. | `false` |
| `invalid` | The certificate was read, but verification failed for another reason: hostname mismatch, untrusted chain, or not yet in effect. | `false` |
| `critical` | Verification OK and `days_remaining <= critical_threshold_days`. | `true` |
| `warning` | Verification OK and `days_remaining <= alert_threshold_days`. | `true` |
| `ok` | Verification OK and the deadline is above the thresholds. | `true` |

### `error_kind` values

A closed vocabulary — no other value appears in the report:

| `error_kind` | Meaning |
| --- | --- |
| `dns` | The name did not resolve. |
| `timeout` | The connection or the handshake exceeded `-timeout`. |
| `refused` | TCP connection refused on the port. |
| `expired` | Expired certificate. |
| `hostname_mismatch` | The certificate is valid, but not for the name that was queried. |
| `untrusted` | The chain does not chain up to a trusted system root. |
| `not_yet_valid` | `NotBefore` has not arrived yet. |
| `no_certificate` | The server completed the connection but presented no certificate. |
| `protocol` | TLS protocol error (incompatible version, malformed handshake, a service that does not speak TLS on that port). |
| `other` | Any other failure that does not fit the ones above. |

### Why `expired` and `invalid` still carry certificate data

When TLS verification fails, the checker reconnects with verification disabled
**only to extract the certificate metadata** — validity, issuer, SANs — so the
dashboard can show *what* is wrong and *since when*. That reconnection is
strictly diagnostic: the `status` remains `expired` or `invalid`, and the
domain is never considered valid because of it.

Since that data comes from an **unverified** handshake, it only describes what
the server presented — it does not prove its identity. Whoever sits on the
connection path controls what shows up there. That is why the result carries
`metadata_insecure: true`, and why the dashboard labels the detail panel as
diagnostic data. Use it to investigate the problem, never as evidence that the
certificate belongs to who it claims.

### Compatibility with the old format

Earlier versions wrote a bare JSON array, with no envelope. The dashboard
accepts both: when it finds an array it normalizes it to
`{"schema_version": 1, "results": [...]}`. v1 reports have no summary, no
thresholds and no granular states — just re-run `sslscout` and the file is
rewritten in the v2 schema.

---

## Serving the dashboard

### Built-in `-serve` mode

```sh
./sslscout -serve :8080
```

Checks the domains, writes the report and brings up a static HTTP server on the
`-out` directory (by default `public/`). Useful for development and for
internal-network use. Combined with `-interval` it becomes a long-running
process that refreshes itself:

```sh
./sslscout -serve :8080 -interval 6h
```

> **Warning:** `-serve` mode has no authentication, no TLS and no access
> control. Do not expose that port to the internet. See
> [Security](#security).

### nginx

Leave `sslscout` running from cron/systemd and serve the `public/` directory
with nginx. There is a ready-made vhost in
[`examples/nginx/sslscout.conf`](examples/nginx/sslscout.conf):

```nginx
server {
    listen 80;
    server_name sslscout.internal.example.com;
    root /opt/sslscout/public;
    index index.html;

    location = /report.json {
        add_header Cache-Control "no-store, no-cache, must-revalidate" always;
        expires -1;
        default_type application/json;
    }

    location / {
        try_files $uri $uri/ =404;
    }
}
```

### Apache

```apache
<VirtualHost *:80>
    ServerName sslscout.internal.example.com
    DocumentRoot /opt/sslscout/public

    <Directory /opt/sslscout/public>
        Require ip 10.0.0.0/8
        Options -Indexes
        AllowOverride None
    </Directory>

    # The report changes on every run; it must not be cached.
    <Files "report.json">
        Header set Cache-Control "no-store, no-cache, must-revalidate"
    </Files>
</VirtualHost>
```

The `<Files>` block requires the `headers` module
(`a2enmod headers` on Debian/Ubuntu).

### GitHub Pages

The workflow [`.github/workflows/pages.yml`](.github/workflows/pages.yml)
builds SSLScout on the runner, runs the check with `-notify=false`, and
publishes the `public/` directory to GitHub Pages. It runs on demand
(`workflow_dispatch`) and once a day.

To enable it: **Settings → Pages → Build and deployment → Source: GitHub
Actions**.

> **Warning:** in a public repository the published dashboard is public, and so
> is your domain list. Do not use Pages for an internal fleet.

---

## Docker

```sh
make docker              # or: docker build -t sslscout:latest .
```

The final image is Alpine with `ca-certificates` (without the root
certificates **every** verification would fail as `untrusted`) and `tzdata`,
and it runs as a non-root user (uid 10001). The binary is static
(`CGO_ENABLED=0`).

### Docker Compose (checker + nginx)

This is the shape most people want: one container that checks and one that
serves the dashboard as plain static files. Both are defined in
[`docker-compose.yml`](docker-compose.yml) at the repository root.

```sh
# 1. Configuration. Create config.json BEFORE the first "up" — if it is
#    missing, Docker helpfully creates a DIRECTORY in its place.
cp config.example.json config.json
chmod 600 config.json
$EDITOR config.json

# 2. Optional: secrets and settings for compose.
cp examples/docker/env.example .env
$EDITOR .env

# 3. Up.
docker compose up -d --build      # or: make up
open http://localhost:8080
```

`make up` refuses to start when `config.json` is missing, precisely to avoid
that directory trap.

What the two services do:

| Service | Image | Role |
| --- | --- | --- |
| `sslscout` | built from the `Dockerfile` | Runs the check and rewrites `report.json` every `SSLSCOUT_INTERVAL` (12h by default). It never listens on a port. |
| `web` | `nginx:1.27-alpine` | Serves `public/` as static files on `127.0.0.1:8080`. It knows nothing about SSLScout. |

They exchange data through the named volume `public`. A volume rather than a
bind mount avoids the usual permission fight: the image runs as uid 10001, and
a host directory owned by your user would not be writable by it. On the first
`up` Docker seeds the volume with the image content, so the dashboard is there
before the first check finishes. `public/index.html` is *also* bind-mounted
read-only into nginx, so editing the dashboard on the host and reloading the
page is enough — no volume rebuild.

The nginx site lives in
[`examples/docker/nginx.conf`](examples/docker/nginx.conf): no directory
listings, no server tokens, `no-store` on `report.json`, and a commented block
for restricting access by network or with HTTP basic auth.

Useful commands:

```sh
docker compose logs -f sslscout          # or: make logs
docker compose exec sslscout sslscout -version
docker compose run --rm sslscout -notify=false   # one extra check, right now
docker compose down                      # or: make down
docker compose down -v                   # also drops the report volume
```

Settings come from `.env` (see
[`examples/docker/env.example`](examples/docker/env.example)):

| Variable | Default | What it does |
| --- | --- | --- |
| `SSLSCOUT_INTERVAL` | `12h` | How often the check re-runs. |
| `SSLSCOUT_LANG` | `en` | Alert language (`en` or `pt-BR`). |
| `TZ` | `UTC` | Time zone of the container log. |
| `SSLSCOUT_BIND` | `127.0.0.1` | Interface nginx is published on. |
| `SSLSCOUT_PORT` | `8080` | Published port. |
| `SSLSCOUT_SLACK_WEBHOOK_URL` | (empty) | Slack webhook. |
| `SSLSCOUT_TEAMS_WEBHOOK_URL` | (empty) | Teams webhook. |
| `SSLSCOUT_SMTP_USERNAME` | (empty) | SMTP user. |
| `SSLSCOUT_SMTP_PASSWORD` | (empty) | SMTP password. |

`.env` is git-ignored and is the right place for the credentials — they must
never end up inside `docker-compose.yml`.

The bind defaults to `127.0.0.1` on purpose: the dashboard has no
authentication of its own. Publish it more widely only behind a reverse proxy
with TLS and access control.

#### One-shot variant (host scheduler)

If the host already has a scheduler and you would rather not keep a process
sleeping between checks, use
[`examples/docker/docker-compose.oneshot.yml`](examples/docker/docker-compose.oneshot.yml):
nginx stays up, and the checker runs once and exits.

```sh
docker compose -f examples/docker/docker-compose.oneshot.yml up -d web
docker compose -f examples/docker/docker-compose.oneshot.yml run --rm check
```

and in cron:

```cron
30 6 * * *  cd /opt/sslscout && docker compose \
              -f examples/docker/docker-compose.oneshot.yml run --rm check
```

The exit code is the binary's own, so `-fail-on` works and cron reports a
failing run.

### Plain `docker run`

Single run, mounting the list and the configuration from outside and receiving
the report in a host directory:

```sh
docker run --rm \
  -v "$PWD/domains.txt:/app/domains.txt:ro" \
  -v "$PWD/config.json:/app/config.json:ro" \
  -v "$PWD/public:/app/public" \
  sslscout:latest
```

Passing the secrets through the environment, with no `config.json` in the
container:

```sh
docker run --rm \
  -v "$PWD/domains.txt:/app/domains.txt:ro" \
  -v "$PWD/public:/app/public" \
  -e SSLSCOUT_SLACK_WEBHOOK_URL \
  -e SSLSCOUT_SMTP_PASSWORD \
  -e SSLSCOUT_LANG=pt-BR \
  sslscout:latest -domains /app/domains.txt -out /app/public/report.json
```

Long-running service, serving the dashboard and re-running every 6 hours:

```sh
docker run -d --name sslscout \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/domains.txt:/app/domains.txt:ro" \
  -v "$PWD/config.json:/app/config.json:ro" \
  -e TZ=America/Sao_Paulo \
  sslscout:latest \
    -domains /app/domains.txt \
    -config /app/config.json \
    -out /app/public/report.json \
    -serve :8080 \
    -interval 6h
```

Note the `-p 127.0.0.1:8080:8080`: publishing it as `-p 8080:8080` would leave
the unauthenticated dashboard reachable on every interface of the machine.

The directory mounted at `/app/public` has to be writable by uid 10001, since
that is where `report.json` is written. The Compose setup sidesteps this by
using a named volume.

---

## Scheduling

### cron

A complete example lives in [`examples/crontab`](examples/crontab):

```cron
# /etc/cron.d/sslscout
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=sre@example.com

30 6 * * *   sslscout   cd /opt/sslscout && ./sslscout -quiet
```

`-quiet` keeps cron silent while everything is fine: there is output (and
therefore mail to `MAILTO`) only when something goes wrong.

### systemd

A ready unit and timer live in [`examples/systemd/`](examples/systemd/):

```sh
sudo install -m 0644 examples/systemd/sslscout.service /etc/systemd/system/
sudo install -m 0644 examples/systemd/sslscout.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sslscout.timer

systemctl list-timers sslscout.timer
journalctl -u sslscout.service -n 50
```

The unit is `Type=oneshot`, runs as the `sslscout` user, reads secrets from
`/etc/sslscout/secrets.env` (optional) and comes with systemd isolation turned
on (`ProtectSystem=strict`, `NoNewPrivileges`, syscall filter). The only
writable directory is `/opt/sslscout/public`, where the report is written.

### No external scheduler

If you prefer a long-running process over cron:

```sh
./sslscout -interval 6h -serve :8080
```

---

## Notifications

Alerts are sent when there are results in an alert state. Each channel is
enabled individually and they can all coexist. To test without bothering
anyone, run with `-notify=false` until you are happy with the report.

The alert text is English by default and can be switched to Brazilian
Portuguese — see [Languages](#languages-i18n).

### Slack

1. Go to <https://api.slack.com/apps> and click **Create New App → From
   scratch**. Give it a name (e.g. `SSLScout`) and pick the workspace.
2. In the sidebar, open **Incoming Webhooks** and turn on **Activate Incoming
   Webhooks**.
3. Click **Add New Webhook to Workspace**, pick the destination channel and
   authorize it.
4. Copy the generated URL — it looks like
   `https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX`.

That URL **is** the credential: whoever has it can post to your channel. Prefer
supplying it through the environment:

```sh
export SSLSCOUT_SLACK_WEBHOOK_URL='https://hooks.slack.com/services/T00000000/B00000000/XXXX'
```

or, in `config.json`:

```json
{ "slack_webhook_url": "https://hooks.slack.com/services/T00000000/B00000000/XXXX" }
```

### Microsoft Teams

1. In Teams, open the destination channel and click the three dots →
   **Connectors** (on newer tenants: **Workflows** → the *Post to a channel
   when a webhook request is received* template).
2. Choose **Incoming Webhook**, give it a name (e.g. `SSLScout`) and confirm.
3. Copy the generated URL. It points at a `*.webhook.office.com` domain (or
   `*.logic.azure.com` in the Workflows case).

```sh
export SSLSCOUT_TEAMS_WEBHOOK_URL='https://example.webhook.office.com/webhookb2/...'
```

As with Slack, the URL is the credential.

### E-mail — Gmail with an app password

Gmail does not accept the account password over SMTP. You need an **app
password**, which requires two-step verification to be active on the account:

1. Turn on two-step verification at <https://myaccount.google.com/security>.
2. Go to <https://myaccount.google.com/apppasswords>, create a password for
   "SSLScout" and copy the 16 characters it generates.
3. Use that value as `smtp.password` (preferably through
   `SSLSCOUT_SMTP_PASSWORD`).

```json
{
  "smtp": {
    "enabled": true,
    "host": "smtp.gmail.com",
    "port": 587,
    "username": "alerts@yourdomain.com",
    "password": "",
    "from": "alerts@yourdomain.com",
    "to": ["sre@yourdomain.com"],
    "tls": "starttls"
  }
}
```

```sh
export SSLSCOUT_SMTP_PASSWORD='abcdefghijklmnop'   # the app password, no spaces
./sslscout
```

To use port 465 instead of 587, switch to `"port": 465` and
`"tls": "implicit"`.

### E-mail — internal relay

A corporate relay that accepts the internal network without authentication:

```json
{
  "smtp": {
    "enabled": true,
    "host": "relay.internal.example.com",
    "port": 25,
    "username": "",
    "password": "",
    "from": "sslscout@example.com",
    "to": ["sre@example.com", "noc@example.com"],
    "tls": "none"
  }
}
```

If the relay supports STARTTLS on 25 or 587, prefer `"tls": "starttls"` —
`none` leaves the message (and the password, if any) in the clear on the wire.

---

## Security

- **Never commit `config.json`.** It holds the SMTP password and the webhook
  URLs, which are full credentials. The project `.gitignore` already blocks
  `config.json` and `config.*.json` while keeping `config.example.json`
  versioned. Before any commit, check with `git status` that the file does not
  show up. The same goes for `.env`, used by Docker Compose.
- **Prefer environment variables for secrets.** The `SSLSCOUT_*` variables
  override the corresponding fields, which lets you keep a `config.json` with
  nothing sensitive in it and pass the credentials through systemd
  (`EnvironmentFile=`), Docker (`-e`, or `.env` with Compose) or whichever
  secret manager you already use.
- **Restrict the permissions of the configuration file:**

  ```sh
  sudo chown sslscout:sslscout /opt/sslscout/config.json
  sudo chmod 600 /opt/sslscout/config.json
  ```

  The same applies to `/etc/sslscout/secrets.env`, if you use the example
  systemd unit.
- **`-serve` mode has no authentication, no TLS and no access control.** It
  serves the report directory to anyone who can reach the port. Do not expose
  it to the internet. If you need remote access, put it behind a reverse proxy
  with TLS and authentication (the nginx and Apache examples show how), or
  publish it with `-p 127.0.0.1:8080:8080` and reach it through an SSH tunnel.
- **The domain list is sensitive information.** `domains.txt` and the generated
  `report.json` describe your network surface — internal hosts included. Think
  twice before publishing the dashboard in a public repository or site.
- **If a secret leaks**, revoke it at the source (regenerate the webhook in
  Slack/Teams, revoke the app password with Google). Removing the file from
  disk does not invalidate the credential.

---

## Troubleshooting

Start with the `error_kind` field of `report.json` — it is what tells you which
kind of problem you have.

| `error_kind` | What happened | What to do |
| --- | --- | --- |
| `dns` | The name did not resolve. | Check the spelling in `domains.txt`. Test with `dig +short your.domain.com`. In a container, remember the resolver is the container's, not the host's — internal names may not exist there. |
| `timeout` | The connection or the handshake did not finish within `-timeout`. | Test with `openssl s_client -connect host:443`. A firewall or security group blocking the port is the most common cause. If the server is merely slow, raise `-timeout` or `timeout_seconds`. Too high a `-concurrency` can also cause mass timeouts: lower it. |
| `refused` | TCP was refused on the port. | The service is down, or the port in the `domains.txt` entry is wrong. Confirm with `nc -vz host port`. |
| `expired` | The certificate expired. | Renew and redeploy the certificate. Check `expires_at` in the report to see how long ago. If you renewed and the error persists, the service probably did not reload the new certificate. |
| `hostname_mismatch` | The certificate is valid, but does not cover the name that was queried. | Compare the `dns_names` field of the report with the name you listed. Typical causes: a missing SAN, the host answering with the server's default certificate, or a misconfigured vhost/SNI. |
| `untrusted` | The chain does not reach a trusted root. | Usually the intermediate certificate is missing on the server: check with `openssl s_client -showcerts -connect host:443`. With an internal CA, install the root in the system store — in a container, mount it and run `update-ca-certificates`. If **every** domain came back `untrusted`, the problem is the environment: the `ca-certificates` package is missing. |
| `not_yet_valid` | `NotBefore` has not arrived yet. | Almost always the clock of the machine running SSLScout is wrong. Check `timedatectl` / NTP. It can also be a certificate issued with a future date. |
| `no_certificate` | The connection completed but no certificate was presented. | The port probably does not speak TLS (e.g. 80 instead of 443), or the service requires SNI and has no default certificate. |
| `protocol` | TLS protocol error. | The service may not speak TLS on that port, or may only accept old versions Go refuses. Check with `openssl s_client -connect host:port`. |
| `other` | Unclassified failure. | Read the `error` field, which carries the original message. |

Other common problems:

**The dashboard shows "could not load" or stays empty.**
`report.json` has not been generated yet — it does not ship in the repository.
Run `./sslscout` once. Also check that the file is in the **same directory** as
`index.html`: the dashboard fetches `report.json` by relative path.

**I double-clicked `index.html` and nothing loads.**
Over `file://` the browser blocks the `report.json` request under the
same-origin policy. Use `./sslscout -serve :8080` or any static HTTP server.

**The dashboard shows stale data.**
Force a cacheless reload (Ctrl+Shift+R). `-serve` mode already sends
`Cache-Control: no-store` for `report.json`; if you serve through nginx or
Apache, apply the headers from the examples above.

**Every domain comes back `untrusted` inside the container.**
`ca-certificates` is missing from the image. The `Dockerfile` in this
repository already installs it.

**Notifications are not going out.**
Confirm you are not running with `-notify=false`, that the channel has a value
configured (an empty webhook disables the channel, and `smtp.enabled` has to be
`true`) and that there really is a result in an alert state — when everything
is `ok`, nothing is sent.

**E-mail fails with an authentication error on Gmail.**
The account password does not work; you need an app password (see
[Notifications](#e-mail--gmail-with-an-app-password)).

**`-notify` on its own does not turn notifications off.**
It is a boolean flag defaulting to `true`; write `-notify=false`.

**The alerts arrived in the wrong language.**
Precedence is `-lang` > `SSLSCOUT_LANG` > `language` in `config.json` >
`en`. In Docker Compose, `SSLSCOUT_LANG` comes from `.env`, which beats
`config.json`.

**Compose created a directory named `config.json`.**
That is what Docker does when a bind-mount source is missing. Remove the
directory, create the file, and bring it up again:
`docker compose down && rmdir config.json && cp config.example.json config.json`.

---

## Development

### Project layout

```
.
├── cmd/sslscout/        # main: flags, orchestration, exit codes
├── pkg/checker/         # TLS connection, certificate reading, classification
├── pkg/config/          # loading config.json and the environment variables
├── pkg/report/          # building and writing report.json
├── pkg/notifier/        # Slack, Microsoft Teams, SMTP
├── pkg/i18n/            # message catalogs for the notifications
├── public/
│   ├── index.html       # single-file static dashboard (with its own catalogs)
│   └── report.json      # generated at run time (not versioned)
├── examples/
│   ├── crontab          # cron scheduling
│   ├── systemd/         # oneshot unit + timer
│   ├── nginx/           # vhost for the static dashboard
│   └── docker/          # nginx.conf, .env template, one-shot compose
├── .github/workflows/   # CI and GitHub Pages publishing
├── config.example.json  # template for config.json
├── domains.txt          # domain list
├── docker-compose.yml   # checker + nginx
├── Dockerfile
└── Makefile
```

### Makefile targets

The Makefile works with both GNU make and BSD make. `make` with no arguments
prints the help.

| Target | What it does |
| --- | --- |
| `make help` | Lists the targets (default). |
| `make build` | Builds `sslscout`, injecting the version into `main.version`. |
| `make run` | Builds and runs one check. |
| `make serve` | Builds, checks and serves the dashboard (`SERVE_ADDR`, default `:8080`). |
| `make test` | `go test -race ./...`. |
| `make fmt` | `gofmt -w -s .`. |
| `make vet` | `go vet ./...`. |
| `make lint` | Fails on any badly formatted file, then runs `go vet`. |
| `make clean` | Removes the binary, the coverage artifacts and `public/report.json`. |
| `make docker` | Builds the image (`DOCKER_IMAGE:DOCKER_TAG`). |
| `make up` | `docker compose up -d --build` (refuses to run without `config.json`). |
| `make down` | `docker compose down`. |
| `make logs` | Follows the checker logs. |

### Tests

```sh
go test ./...
go test -race ./...
go test -race -coverprofile=coverage.out ./... && go tool cover -html=coverage.out
```

Tests must not depend on the external network — CI runs without guaranteed
access to third-party hosts, and a test that talks to the internet turns flaky.

### CI

The workflow [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on
every push and pull request, on a matrix with Go 1.21 (the minimum in
`go.mod`) and stable Go, running: `gofmt -l .` (failing on any output),
`go vet ./...`, `go build ./...` and `go test -race ./...`.

### Why `report.json` is not versioned

`public/report.json` is **generated output**, not source, and it is in
`.gitignore`. The reasons:

- it changes on every run, which would produce one noise commit per day;
- it describes the network surface of whoever ran the tool, internal hosts
  included — not something that should reach a repository by accident;
- a versioned report goes stale and misleads: the dashboard would show days
  remaining computed weeks ago.

The consequence is that in a fresh clone the dashboard shows the empty state
until the first run. That is the correct behaviour: an empty dashboard is
honest, a dashboard with somebody else's data is not. To fill it in, run
`./sslscout` (or `make run`).

`.gitignore` only applies to files that are not yet tracked. If
`public/report.json` is already in the Git index from an earlier commit, untrack
it once (the file stays on disk):

```sh
git rm --cached public/report.json
git commit -m "report.json is generated output, not source"
```

### Contributing

- Keep the **zero external dependencies** rule: only the Go standard library on
  the backend, and no CDN, remote font or external request in
  `public/index.html`.
- Code, comments and documentation in English. User-facing alert and dashboard
  text goes through the catalogs described in
  [Languages](#languages-i18n) — never hard-code a visible string.
- Run `make lint` and `make test` before opening a PR — that is what CI checks.
- Breaking changes to the `report.json` format must bump `schema_version` and
  update this documentation.

---

## License

BSD 2-Clause. See [LICENSE](LICENSE).
