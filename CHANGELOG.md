# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-23

First public release.

### Added

- Collection of DMARC aggregate reports from an IMAP folder, in the background: Gmail / Google
  Workspace with OAuth (consent of the mailbox owner) or user and password on any IMAP server;
  read-only or read-write mode (mark as read, move or delete).
- Parser for RFC 7489 and DMARCbis reports (zip, gzip, XML) and manual import of files.
- Dashboard (Tools › DMARC): summary, evolution, sending sources, failures by cause,
  recommendations, reports, alerts and collection; filter by period, one or several domains,
  reporting organization and grouping.
- Classification of the sending sources, reverse names and optional AbuseIPDB reputation (cached per IP).
- GLPI notifications for unauthorized sources, failing authorized sources, domains without reports,
  collection errors and a weekly summary, with a global switch.
- Plugin entity, own profile right, retention up to 36 months.
- English and Spanish translations.
- One-line installer (`install.sh`).
