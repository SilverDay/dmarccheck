# DMARC Report Analyzer — starter package

Scaffold for the self-hosted DMARC aggregate report analyzer described in
`dmarc-report-analyzer-spec.md`. PHP 8.3 (strict types), MariaDB 10.11+,
Apache, PDO, front-controller routing, no heavy framework.

> **Status: scaffold, not a finished application.** See *What's implemented*
> below for an honest split. The ingestion path is the most complete part;
> the dashboard, recommendation engine, health check and auth are stubs.

---

## Quick start (VS Code)

```bash
composer install
cp config/config.sample.php config/config.php   # then fill in
mysql -u root -p -e "CREATE DATABASE dmarc CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u dmarc -p dmarc < db/schema.sql
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
| `load schema` | apply `db/schema.sql` |
| `serve (dev)` | `php -S 127.0.0.1:8080 -t public` |
| `run ingest` | one ingestion pass |

Debugging uses Xdebug on port 9003 (`.vscode/launch.json` has configs for
listening, for `bin/ingest.php`, and for the current file). Adjust
`pathMappings` if you debug against the VPS rather than locally.

---

## Layout

```
bin/          CLI entrypoints (cron)
config/       config.sample.php → copy to config.php (gitignored)
db/           schema.sql, seed-domains.sql
public/       Apache DocumentRoot — front controller only
src/          PSR-4 App\ namespace
  Http/       Router
  Ingest/     Decompressor, ReportParser, ParsedReport, ReportStore
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
- Schema for reports, enrichment, recommendations, health checks, users/auth
  and audit log.

**Stubs / not yet written:**
- `bin/enrich.php` — rDNS + ASN lookup, allowlist labelling (§6)
- `bin/healthcheck.php` — DNS/DNSBL/transport checks (§11)
- `bin/analyze.php` — the R1–R12 rule engine (§10)
- `bin/alert.php` — alerting incl. the heartbeat (§8)
- Dashboard beyond a bare domain list (§7)
- Authentication, RBAC, invitations, passkeys (§15) — schema exists, no code

---

## Verify before you rely on it

This scaffold could not be executed in the environment it was written in
(no PHP runtime available), so treat it as **reviewed-but-unrun code**.
Before trusting it:

1. `composer install && vendor/bin/phpunit` — confirm the tests pass.
2. `vendor/bin/phpstan analyse src bin --level=6` — confirm it's clean.
3. `composer audit` — check advisories for the pinned dependencies.
4. Confirm dependency versions resolve as intended:
   - `webklex/php-imap` ^6.0 (6.2.0 current at time of writing; needs
     `ext-mbstring`)
   - `web-auth/webauthn-lib` ^5.0 — **verify this constraint**; the
     WebAuthn packages have restructured across major versions.
5. Test the parser against **real** reports from several providers before
   trusting it in production — vendor XML deviates from the schema
   constantly. Collecting that corpus is a standing task in spec §16.

---

## Operational notes

**Cron:**
```cron
*/20 * * * *  php /srv/dmarc/bin/ingest.php >> /var/log/dmarc/ingest.log 2>&1
15   3 * * *  php /srv/dmarc/bin/alert.php  >> /var/log/dmarc/alert.log  2>&1
```

**Apache:** DocumentRoot → `public/`. Everything else stays outside the
web root. `.htaccess` routes to the front controller and denies dotfiles.

**Database privileges:** grant the app `INSERT, SELECT` on `audit_log`
only — no `UPDATE`/`DELETE`, so the audit trail is append-only in practice
and not merely by convention.

**Secrets:** `config/config.php` is gitignored. It holds DB credentials,
the IMAP password, and the MaxMind/Spamhaus DQS keys. Keep it `0640`,
owned by the web/CLI user.
