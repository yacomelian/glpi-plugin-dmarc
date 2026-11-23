# DMARC plugin for GLPI

[Español](README.es.md)

Collects the **DMARC aggregate reports** (RUA) that mail receivers (Google, Microsoft, Yahoo…) send
about your domains, from an IMAP mailbox, and shows them in GLPI under **Tools › DMARC**: who sends mail
as your domains, what passes and fails SPF/DKIM/DMARC and why, and when the policy can be tightened.

* GLPI **11.0** and **12.0** · PHP **8.2+** · License **GPLv2+**
* Languages: English, Spanish (`locales/`; translations welcome)

## Features

* **Collection** from one mailbox folder (`DMARC` by default), in the background, without blocking GLPI:

  * **Gmail / Google Workspace with OAuth** (consent of the mailbox owner; no service account, no
domain-wide delegation) or **user and password** on any IMAP server. Own IMAP client: the PHP `imap`
extension is not needed.
  * **Read-only** by default (EXAMINE + BODY.PEEK: nothing changes in the mailbox), or **read-write**:
mark as read, move to another folder or delete what was processed.
  * Manual import of `.eml`, `.zip`, `.gz` and `.xml` files (web or console).
* **Parsing** of RFC 7489 and DMARCbis reports (zip, gzip, plain XML), with size limits and without
DTDs/entities. Each report is stored once; the original XML can be kept (compressed).
* **Dashboard** with filters (period, one or several domains, reporting organization, grouping):

  * **Summary**: key figures, comparison with the previous period, status of each domain.
  * **Evolution**: volume, compliance, policy changes, who reports.
  * **Sending sources**: every IP with its reverse name, provider and **AbuseIPDB** reputation (optional,
cached per IP); classify them as authorized, forwarder or unauthorized.
  * **Failures**: grouped by cause with a plain explanation (forwarding, unaligned SPF, DKIM of another
domain, broken DKIM, no authentication) and the DKIM selectors seen.
  * **Recommendations**: fixed rules (p=none → quarantine → reject, pct, sp, silent domains…).
  * **Reports** with their full detail and the original XML.
  * **Alerts** and **Collection** (mailbox status, processed mails, reprocess, import).
* **GLPI notifications** (Setup › Notifications, type "DMARC alert"): unauthorized or unknown source,
authorized source failing, domain without reports, collection errors, weekly summary. A global switch
in the plugin configuration (off by default).
* **Entity**: the plugin works in one entity (and optionally its sub-entities); the alerts belong to it.
* **Retention**: up to 36 months, cleaned daily.
* Own right **DMARC** in Administration › Profiles: Read (dashboard) and Update (classify, collect,
import, close alerts). The mailbox connection is changed by whoever has the GLPI configuration right.

## Installation

### One-line installer

On the GLPI server (as root or as a user that can write to the GLPI folder):

```sh
curl -fsSL https://raw.githubusercontent.com/yacomelian/main/install.sh | bash
```

It asks for the GLPI folder (and suggests the usual ones), checks that it is GLPI 11 or 12 with the PHP
extensions needed, downloads the latest release, checks its SHA-256, backs up a previous version,
installs it with the owner of the GLPI files and runs `glpi:plugin:install` + `activate`.

Options (also for unattended runs): `--path /var/www/glpi`, `--version 1.0.0`, `--container NAME`
(GLPI in Docker/Podman), `--no-activate`, `--yes`. See `install.sh --help`.

```sh
curl -fsSL https://raw.githubusercontent.com/yacomelian/main/install.sh | bash -s -- --path /var/www/glpi --yes
```

### Manual

1. Download `glpi-dmarc-X.Y.Z.tar.bz2` from the [releases](https://github.com/yacomelian/glpi-plugin-dmarc/releases).
2. Extract it into GLPI's `plugins/` (or `marketplace/`) folder: it creates `dmarc/`.
3. `php bin/console glpi:plugin:install dmarc -u glpi` and `php bin/console glpi:plugin:activate dmarc`
(or Setup › Plugins in the web interface).

### Requirements

* GLPI 11.0.x or 12.0.x, PHP 8.2 or newer with `openssl`, `zlib`, `zip`, `curl`, `mbstring`, `simplexml`.
* GLPI's automatic actions (cron) running.
* Outgoing access from the GLPI server to the IMAP server (`imap.gmail.com:993` for Gmail), and for
OAuth to `oauth2.googleapis.com:443`; for AbuseIPDB to `api.abuseipdb.com:443`. GLPI's proxy
(Setup › General › Proxy) is used for the HTTPS calls.
* Background jobs use PHP's `exec()` on Linux. Without it, the collection runs inside the automatic
action (limited time per run).

## Configuration

Setup › Plugins › DMARC (or the gear in Tools › DMARC).

### Gmail / Google Workspace (OAuth)

The DMARC mailbox is a normal user (for example `dmarc@example.com`); only that user authorizes the access.

1. **Google Cloud** (once): APIs \& Services › Credentials › Create credentials › OAuth client ID, type
"Web application". In "Authorized redirect URIs" enter the address shown in the plugin configuration
(`https://<GLPI URL>/plugins/dmarc/front/oauth.php`; it comes from Setup › General › URL of the
application, and must be https). In the consent screen choose the user type **Internal** (with
"External" in testing mode, Google expires the permission after 7 days).
2. **GLPI**: server `imap.gmail.com`, port 993, SSL, user (the mailbox address), folder `DMARC`, and the
OAuth client ID and secret.
3. **Save and connect with Google**: Google asks to sign in **with the mailbox account** and to allow the
access. The plugin keeps the permission only if the authorized account is the mailbox one.
4. **Save and test the connection.**

"Disconnect" deletes the permission in the plugin; to revoke it in Google too: myaccount.google.com ›
Security › Third-party connections.

### Any IMAP server

Choose "User and password", the server, port and encryption. Gmail no longer accepts the normal
password; app passwords are discouraged by Google: use OAuth there.

### First load

Set "Import mails received since" if the folder is very large, then press **Collect now** in the
Collection tab (it runs in the background and goes on with the automatic action), or from the console:

```sh
php bin/console plugins:dmarc:collect --all
```

## Console

```
php bin/console plugins:dmarc:collect \[--all | --limit=N | --test | --resolve | --check | --summary]
php bin/console plugins:dmarc:import /path/to/files-or-folder
```

## Security

* Secrets (IMAP password, OAuth client secret and refresh token, AbuseIPDB key) are stored **encrypted
by GLPI** (`secured\_configs`) and never shown again in the forms.
* The OAuth permission only gives access to the mailbox that authorized it; the authorized account is
checked against the configured mailbox.
* Reports are untrusted input: no DTD/entities, no network access while parsing, size limits on every
decompression, attachments matched by type; everything shown is escaped.
* Read-only mailbox mode by default.
* All database access uses GLPI's query builder.
* Please report vulnerabilities privately (see [SECURITY.md](SECURITY.md)).

## Development

```sh
php bin/console plugins:dmarc:demo --create      # a year of synthetic reports (domains \*-demo.example)
php bin/console plugins:dmarc:demo --purge       # delete them
php bin/console plugins:dmarc:demo --selftest    # parser, simulated IMAP, Google and AbuseIPDB (tools/)
php bin/console plugins:dmarc:demo --render=DIR  # write every tab as HTML (add --lang=es\_ES)
```

The demo command and the simulators in `tools/` are not included in the release archives.

Translations: `locales/dmarc.pot` is the template; add `locales/xx\_XX.po` and compile it to `.mo`.

## License

GPLv2+ — see [LICENSE](LICENSE). Copyright © 2026 Yaco Melian.

