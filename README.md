# DMARC Report Analyzer — starter package

Scaffold for the self-hosted DMARC aggregate report analyzer described in
`dmarc-report-analyzer-spec.md`. PHP 8.3 (strict types), MariaDB 10.11+,
Apache, PDO, front-controller routing, no heavy framework.

> **Status: scaffold, not a finished application.** See *What's implemented*
> below for an honest split. Ingestion, enrichment, the domain health check,
> the R1–R12 recommendation engine, alerting, auth/RBAC, and the dashboard
> (domain list + per-domain drill-down) are built and unit-tested; domain
> onboarding/policy-approval actions and the community-reporting UI are
> still stubs.

---

## Quick start (VS Code)

```bash
composer install
cp config/config.sample.php config/config.php   # then fill in
mysql -u root -p -e "CREATE DATABASE dmarc CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
php bin/migrate.php
mysql -u dmarc -p dmarc < db/seed-domains.sql   # optional: the 10 domains
vendor/bin/phpunit
```

Open the folder in VS Code and accept the recommended extensions prompt
(`.vscode/extensions.json`). Then:

| Task (⇧⌘P → *Run Task*) | What it does |
|---|---|
| `composer install` | install dependencies |
| `test` | run PHPUnit (default test task) |
| `phpstan` | static analysis at level 6 |
| `migrate` | apply pending `db/migrations/*.sql` |
| `serve (dev)` | `php -S 127.0.0.1:8080 -t public` |
| `run ingest` | one ingestion pass |

Debugging uses Xdebug on port 9003 (`.vscode/launch.json` has configs for
listening, for `bin/ingest.php`, and for the current file). Adjust
`pathMappings` if you debug against the VPS rather than locally.

---

## Layout

```
bin/          CLI entrypoints (cron): ingest, enrich, healthcheck, analyze, alert, migrate
config/       config.sample.php → copy to config.php (gitignored)
db/           migrations/ (applied in order via bin/migrate.php), seed-domains.sql
public/       Apache DocumentRoot — front controller + assets/ (icons.svg, app.css, webauthn.js)
src/          PSR-4 App\ namespace
  Alerting/   Heartbeat/policy-drift/volume/pass-rate checks, digest email
  Auth/       Sessions, invitations, passkeys/TOTP, RBAC roles, step-up re-auth
  Enrichment/ rDNS/ASN lookup, known_senders CIDR matching
  HealthCheck/  Per-check DNS/network probes (SPF, DMARC, DKIM, MX, DNSSEC, STARTTLS, DNSBL, ...)
  Http/       Router, AuthMiddleware, View, SvgBarChart, Controllers/ (incl. per-domain drill-down)
  Ingest/     Decompressor, ReportParser, ParsedReport, ReportStore
  Recommendation/  R1-R12 rule engine, AnalysisContextBuilder, reconciliation
  Support/    Ip helpers
tests/        PHPUnit + fixtures
```

---

## What's implemented

**Working (and unit-tested):**
- `Decompressor` — magic-byte sniffing, streamed gzip inflate with a hard
  ceiling, zip entry-count and size caps. Spec §4.1 decompression-bomb
  defence.
- `ReportParser` — RFC 7489 aggregate report parsing, tolerant per §5
  (malformed `<record>` blocks are skipped and reported, not fatal), with
  the §4.1 XXE posture: no `LIBXML_NOENT`/`LIBXML_DTDLOAD`, `LIBXML_NO_XXE`
  feature-detected for PHP 8.4+, DOCTYPE rejected outright.
- `ReportStore` — idempotent persistence; dedup on content hash and on
  (domain, reporter, report_id).
- `bin/ingest.php` — IMAP poll → decompress → parse → archive → store,
  with failed messages quarantined to a separate folder rather than dropped.
- `bin/enrich.php` — rDNS + local GeoLite2 ASN lookup + `known_senders`
  CIDR labelling (§6), decoupled from ingestion.
- `bin/healthcheck.php` — the full §11.2 DNS/network posture checklist
  (SPF, DMARC, cross-domain report-destination authorization, DKIM
  selector probing, MX, DNSSEC, MTA-STS, TLS-RPT, BIMI, STARTTLS+cert via
  a real SMTP handshake, Spamhaus DQS DNSBL/RHSBL, FCrDNS) with `error`
  kept distinct from `fail` throughout (§11.3).
- Auth/RBAC (§15) — invitation-only accounts, WebAuthn passkeys or
  password+TOTP+recovery-codes, mandatory MFA, deny-by-default RBAC
  (read-only ⊂ admin ⊂ super admin), CSRF, step-up re-auth on sensitive
  actions, append-only audit log.
- `bin/analyze.php` — the R1–R12 rule engine (§10): known/unknown-sender
  auth hygiene, SPF lookup-limit, spoofing-volume, policy-advancement,
  DNS-drift, non-sending, subdomain-`sp`, and forwarder-pattern rules,
  each citing its evidence, with idempotent re-runs and auto-resolution
  when a trigger stops firing (§10.5). Advisory only — never edits DNS.
- Schema migrations (`bin/migrate.php`, `db/migrations/`) — numbered,
  tracked, never edited in place.
- `bin/alert.php` — daily alerting (§8): heartbeat/dead-man's-switch,
  DNS policy drift vs. the approved baseline, unknown-IP volume spikes,
  and DMARC pass-rate regression, combined into one digest email.
- Per-domain drill-down dashboard (§7.2) — overview (policy, a
  dependency-free inline-SVG pass/fail trend chart, latest health-check
  results), a sortable/filterable source-IP table, an open-recommendations
  panel, and a raw per-record report-detail view (with an IDOR guard: a
  report_id belonging to a different domain 404s rather than leaking).

**Stubs / not yet written:**
- §10.8 community threat reporting (Spamhaus) — gated on a T&C/GDPR
  review that hasn't happened; ships disabled either way
- Domain onboarding flow, "approve as baseline" policy action — the
  dashboard has no mutating actions yet, read-only throughout

---

## Verify before you rely on it

The pieces listed as "working" above have been exercised against a real
MariaDB instance and, for `bin/healthcheck.php`, real DNS/SMTP/HTTPS
traffic against live domains (Google's MX, Cloudflare's DS record, etc.) —
not just unit tests. Still worth doing before depending on it further:

1. `composer install && vendor/bin/phpunit` — confirm the tests pass.
2. `vendor/bin/phpstan analyse src bin --level=6` — confirm it's clean.
3. `composer audit` — check advisories for the pinned dependencies.
4. Register a Spamhaus DQS key (spec §11.6) before relying on
   `DnsblCheck` — with `healthcheck.spamhaus_dqs_key` empty, every DNSBL
   item reports `error` by design, never a false "clean." The exact DQS
   keyed-zone hostname format (`healthcheck.dnsbl_zones`) should also be
   confirmed against current Spamhaus docs — no real key was available
   to verify the "listed" response path while building this.
5. Provision the GeoLite2-ASN `.mmdb` file (license-gated, not bundled)
   for `bin/enrich.php`'s ASN lookups — it degrades gracefully without
   one, but ASN-based labelling won't run until it's present.
6. Test the parser against **real** reports from several providers before
   trusting it in production — vendor XML deviates from the schema
   constantly. Collecting that corpus is a standing task in spec §16.

---

## Operational notes

**Cron:**
```cron
*/20 * * * *  php /srv/dmarc/bin/ingest.php >> /var/log/dmarc/ingest.log 2>&1
17,47 * * * * php /srv/dmarc/bin/enrich.php >> /var/log/dmarc/enrich.log 2>&1
0    17 * * 0 php /srv/dmarc/bin/healthcheck.php --trigger=scheduled >> /var/log/dmarc/healthcheck.log 2>&1
30   4 * * *  php /srv/dmarc/bin/analyze.php >> /var/log/dmarc/analyze.log 2>&1
15   3 * * *  php /srv/dmarc/bin/alert.php  >> /var/log/dmarc/alert.log  2>&1
```

`bin/healthcheck.php` shells out to `dig` — install `dnsutils` (Debian/Ubuntu) if it's not already present.

**Apache:** DocumentRoot → `public/`. Everything else stays outside the
web root. `.htaccess` routes to the front controller and denies dotfiles.

**Database privileges:** grant the app `INSERT, SELECT` on `audit_log`
only — no `UPDATE`/`DELETE`, so the audit trail is append-only in practice
and not merely by convention.

**Secrets:** `config/config.php` is gitignored. It holds DB credentials,
the IMAP password, and the MaxMind/Spamhaus DQS keys. Keep it `0640`,
owned by the web/CLI user.
