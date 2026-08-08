# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Self-hosted DMARC aggregate report analyzer (PHP 8.3, strict types; MariaDB 10.11+; Apache; PDO/prepared statements; no framework). Full requirements live in `docs/dmarc-report-analyzer-spec.md` — read it before implementing anything beyond ingestion, since most of the app is still unbuilt against that spec.

**Status: scaffold, not a finished application.** The ingestion path (decompress → parse → store) is complete and unit-tested. `bin/enrich.php`, `bin/healthcheck.php`, `bin/analyze.php`, `bin/alert.php` are stubs. The dashboard is a bare domain list. Auth/RBAC (`src/Http`, users/sessions tables) has a DB schema but no code. Treat this split as current fact, not aspiration — verify against the file before assuming something is implemented.

## Commands

```bash
composer install                                  # install deps
vendor/bin/phpunit                                 # run all tests
vendor/bin/phpunit --filter testMethodName          # run a single test
vendor/bin/phpunit tests/ReportParserTest.php        # run one test file
vendor/bin/phpstan analyse src bin --level=6         # static analysis (also: composer stan)
vendor/bin/php-cs-fixer fix --dry-run --diff         # lint check (also: composer lint)
vendor/bin/php-cs-fixer fix                          # apply lint fixes
php -S 127.0.0.1:8080 -t public                      # dev server
php bin/ingest.php                                   # one ingestion pass (IMAP poll → store)
composer audit                                       # check dependency advisories
```

VS Code tasks (`.vscode/tasks.json`) wrap the same commands, plus `load schema` (`mysql -u dmarc -p dmarc < db/schema.sql`). Xdebug is configured on port 9003 (`.vscode/launch.json`) with a config for `bin/ingest.php` — adjust `pathMappings` there when debugging against the VPS instead of locally.

Setup not covered above: `cp config/config.sample.php config/config.php` and fill in (gitignored, mode `0640`); create the `dmarc` DB and load `db/schema.sql` then optionally `db/seed-domains.sql` (the 10 real domains).

## Architecture

**Ingestion pipeline** (`bin/ingest.php`, the only fully-wired flow): IMAP poll via `webklex/php-imap` (never native `ext/imap` — unmaintained, unbundled in PHP 8.4) → `Decompressor` → `ReportParser` → `ReportStore`. Successes get archived (compressed, filename from content hash — never from the attacker-controlled attachment filename) and the IMAP message moved to the "done" folder; failures move to a "failed" folder for manual inspection rather than being dropped. Re-running ingestion is idempotent — dedup is enforced at the DB layer via `reports.raw_file_hash` and the `(domain_id, reporter_org, report_id)` unique constraint, not in application logic.

**`Decompressor` (`src/Ingest/Decompressor.php`)**: sniffs magic bytes (never trusts filename/Content-Type) to pick gzip/zip/raw-XML. Gzip is inflated through a bounded stream (`inflate_add` in chunks, checked after every chunk) so a decompression bomb is caught mid-stream rather than after full inflation. Zip entries are capped by count and per-entry size before/while reading. This class is the primary defense against hostile `rua` submissions — the `rua` address is public DNS, so anyone can mail it.

**`ReportParser` (`src/Ingest/ReportParser.php`)**: `DOMDocument` + `libxml_use_internal_errors`, never passes `LIBXML_NOENT`/`LIBXML_DTDLOAD` (would re-enable entity substitution), feature-detects `LIBXML_NO_XXE` for PHP 8.4+/libxml 2.13+, and rejects any DOCTYPE outright as defense-in-depth. RFC 7489 elements map to the schema below; per-`<record>` parse failures are caught, logged as warnings on the `ParsedReport`, and skipped rather than failing the whole report — vendor XML deviates from spec constantly. Domain attribution uses `policy_published/domain`, not `report_metadata`, because the latter isn't reliably which-domain-is-this.

**`ReportStore` (`src/Ingest/ReportStore.php`)**: persists a `ParsedReport` idempotently against the schema below.

**Data model** (`db/schema.sql`): `domains` (with three distinct policy fields — `current_published_policy` auto-read from DNS, `approved_baseline_policy` requires explicit admin approval, `target_policy` the desired end state; these serve different purposes and must not be collapsed into one field) → `reports` → `report_records` (one per source IP, `source_ip` as `VARBINARY(16)` via `INET6_ATON` for v4/v6 uniformity — see `src/Support/Ip.php`) → `auth_results`. Separately: `ip_enrichment`, `known_senders` (manual allowlist), `recommendations` (rule-engine output), `health_checks`/`health_check_items`, and the auth tables (`users`, `webauthn_credentials`, `recovery_codes`, `invitations`, `password_resets`, `sessions`, `audit_log`).

**Config** (`src/Config.php`): dot-path lookup (`$config->get('imap.host')`) over the array returned by `config/config.php`, loaded once. `require()` throws if a key is missing/empty — use it for anything that must not silently default. `Database::connect()` is a lazy singleton PDO with `EMULATE_PREPARES` off (real server-side prepared statements, not client-side interpolation).

## Conventions from the spec worth knowing before touching related code

- **Recommendation engine (spec §10)**: rules (R1–R12) must be encoded as data/config, not hardcoded conditionals, and every recommendation must cite the exact evidence records that triggered it. `known` vs `unknown` sender classification changes a finding's meaning, not just its severity.
- **Never recommend inbound blocking from `rua` data alone** (spec §9.4/§10.1) — a domain spoofing *to* third parties isn't necessarily hitting this server; only "investigate," never "block," unless also observed on the local MX.
- **Health checks** (`bin/healthcheck.php`, spec §11) must distinguish `error` (DNS timeout, blocklist query failure) from `fail` (confirmed bad) — an unresolvable check is not a passing check. DNSBL/RHSBL lookups go through Spamhaus's free DQS (keyed), not the public mirrors, which block non-attributable resolvers including most hosting networks (spec §11.6).
- **Auth** (spec §15): three global roles (read-only ⊂ admin ⊂ super admin), invitation-only account creation, MFA mandatory for everyone (passkey preferred, TOTP+password fallback), server-side role enforcement on every endpoint — the router explicitly does not grant access by route registration alone (see the NOTE in `src/Http/Router.php`).
- **Data protection** (spec §14): most `source_ip` values are mail-server IPs operated by organizations, not GDPR personal data, but a residual subset (self-hosters, compromised residential hosts) can be — don't assume either blanket position when touching enrichment/storage/retention code.
