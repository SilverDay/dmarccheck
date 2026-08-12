# Feature Enhancements — Beyond the Core Spec

**Status:** Backlog / post-v1 ideas
**Scope:** Quality-of-life, operational excellence, and scaling improvements for larger deployments.

The core project is [feature-complete against the spec](../README.md#whats-implemented). This document captures ideas for incremental enhancements that would improve the tool for broader adoption or tier-down to smaller/solo operators.

**2026-08-12 triage note:** this deployment is a private, invitation-only tool for one internal team running ~10 domains (`db/seed-domains.sql`) — not a multi-tenant SaaS or consulting platform (see `docs/feature-landing-page.md`: no signup path exists by design). Items below are split into what actually fits that reality vs. what was scoped for a much bigger deployment. See "Deferred" section at the bottom before picking up any of those.

---

## 1. REST API Endpoint Layer

**Motivation:** While the web UI is the primary interface, programmatic access enables integration with external tooling (Slack bots, custom monitoring dashboards, external ticketing systems) without polling the UI.

**Scope:**
- Read-only endpoints for:
  - List domains with current status (policy, last-ingest time, open-recommendation counts)
  - Get domain drill-down (source table, pass/fail trend, open recommendations)
  - List recommendations (filterable by domain, severity, rule ID)
  - Recent alerts (heartbeat, policy-drift, volume, pass-rate)
  - Health-check results (per domain, per check)
- **No authentication bypass:** endpoints require API key (bearer token) + optional rate limiting per key.
- **No write operations** in v1 (advisory-only tool; DNS/policy changes stay manual).

**Example use case:**
```bash
curl -H "Authorization: Bearer $DMARC_API_KEY" \
  'https://dmarc.example.com/api/v1/domains?sort=severity'
```

**Effort:** Medium. Reuse existing data-access layer (`AnalysisContextBuilder`, controllers); add middleware for API key validation + JSON serialization.

---

## 3. Report Filtering, Search & Export

**Motivation:** The dashboard shows per-domain drill-down, but forensics or compliance audits often need "show me all unknown-source records from the last 30 days across all domains" and to export for external analysis or regulatory submission.

**Scope:**
- Dashboard enhancements:
  - Date-range picker (last 7/30/90 days, custom range).
  - Filter source table by: label (known/unknown), DKIM/SPF/alignment result, disposition, ASN/org.
  - Cross-domain view: option to search/filter across all domains, not just one.
- Export:
  - CSV download: domain, source IP, rDNS, ASN org, label, volume, DKIM result, SPF result, disposition, date range.
  - Raw report ID list for manual inspection.
- **Performance:** add DB indexes on (domain_id, date_range, label) for fast filtering.

**Example use case:**
```
Analyst needs to generate a Q3 compliance report:
→ "Unknown sources, last 90 days, disposition=reject" → export CSV → pivot in Excel by domain
```

**Effort:** Medium. UI work + query optimization; filtering logic already exists in `AnalysisContextBuilder`.

---

## 4. Policy Staging & Dry-Run / Simulation

**Motivation:** The recommendation engine suggests policy advances (R7/R8), but there's no way to preview "what would happen if I changed the policy now?" without manually re-analyzing with a different policy value.

**Scope:**
- Admin UI: "Test Policy" card on domain overview.
  - Input: trial policy value (e.g., `p=quarantine; pct=50`).
  - Output: re-run analysis with that policy value → show recommendations that would change, disposition impact (how many records would move from `none` → `quarantine`).
  - Visualization: "X% of mail would be quarantined instead of delivered."
- **No DNS change.** Purely a "what-if" view backed by a temporary policy override in `AnalysisContextBuilder`.

**Example use case:**
```
Domain at p=none with R7 ("safe to move to quarantine").
→ Click "Test Policy p=quarantine" → see which sources would change disposition
→ Confirm the impact matches expectation → apply for real
```

**Effort:** Low-to-medium. Minimal new data fetches; mostly conditional UI logic.

---

## 5. Webhook Alerting

**Motivation:** `bin/alert.php` sends email only. Slack/Teams/PagerDuty/custom-HTTP integration avoids polling email.

**Scope:**
- Config: `alerting.webhooks[]` array:
  ```php
  'webhooks' => [
      'slack' => 'https://hooks.slack.com/services/...',
      'custom' => 'https://ticketing.example.com/api/alerts',
  ],
  ```
- `bin/alert.php` changes:
  - After sending email, POST each alert type (heartbeat, drift, volume, pass-rate) as JSON to each configured webhook.
  - Payload includes: alert type, domain, severity, detail, actionable link.
  - Retry logic (exponential backoff, 3 attempts) for transient failures.
  - Signature HMAC on POST body (optional, for webhook verification).
- **Audit:** every webhook POST is logged in `audit_log` (webhook URL, response status, timestamp).

**Example Slack payload:**
```json
{
  "type": "heartbeat",
  "domain": "example.com",
  "severity": "high",
  "detail": "No DMARC reports received for 3 days",
  "link": "https://dmarc.example.com/domain/example.com",
  "timestamp": "2026-08-11T15:30:00Z"
}
```

**Effort:** Medium. Requires an HTTP client (this codebase uses `stream_context_create()`/`file_get_contents()`, not Guzzle — see `MtaStsCheck`), retry logic, payload templating.

---

## 7. Custom Alerting Rules Builder

**Motivation:** Thresholds are currently hardcoded: `unknown_ip_volume = 50`, `pass_rate_drop_pct = 10`. Fine-grained control without editing `config.php`.

**Scope:**
- Super Admin UI: "Alerting Config" page.
  - Editable thresholds: unknown IP volume (R5/R6 trigger), pass-rate drop %, heartbeat window. Policy-drift stays always-on, not tunable.
  - Per-domain overrides (optional): e.g. a reseller-heavy domain sets its unknown-IP threshold higher to cut false positives.
  - Save to DB (`settings` table or extended `domains` columns).
- **Audit:** every threshold change is logged.

**Effort:** Low. Mostly DB/UI work; logic already parameterized in `bin/alert.php`.

---

## 8. Audit Log Search & Visualization

**Motivation:** The audit-log viewer exists (Super Admin only, spec §15.7) but is appendix-style — no search/filter.

**Scope:**
- Full-text search by action, actor email, affected domain.
- Facets: action type, user, domain, date range, success/failure.
- Time-series chart: login attempts over time, policy changes by week.
- Export as CSV.
- **Performance:** add indexes on (actor_user_id, action, timestamp).

**Effort:** Medium. Query optimization + charting (no JS charting library exists yet — the dashboard's trend chart is a hand-rolled inline SVG, `SvgBarChart`, specifically to avoid vendoring one under the strict CSP; reuse that approach rather than introducing Chart.js).

---

## 9. SPF / DKIM Configuration Snippet Generator

**Motivation:** Health check reports SPF/DKIM issues but doesn't output ready-to-apply DNS records. Reducing copy-paste friction speeds remediation.

**Scope:**
- Per-domain "Configuration Snippets" card (Admin+ tier):
  - **SPF:** for each R1 finding (known sender failing SPF) — show current SPF record, suggest an updated record with the sender's include/IP added, warn if the new record would exceed the 10-DNS-lookup limit.
  - **DKIM:** for R2 (known sender failing DKIM but passing SPF) — explain which signing domain/selector needs enabling, link to the evidence (source IP/domain from reports).
  - **DMARC:** already generates the `<policy>._report._dmarc.<destination>` cross-domain record (§7.2) — this item is the same idea applied to SPF/DKIM.
- **Scope note:** advisory only — tool never edits DNS.

**Note:** this fully subsumes the SPF and DMARC portions of item **#16 (DNS Record Builder Wizards)** below — both parse/validate/suggest records off the same evidence. If both are ever built, do this one first and treat #16 as "add the from-scratch wizard UI around it," not a separate implementation.

**Effort:** Medium. Requires SPF parsing (likely already present in `HealthCheck` code), validation logic, templating.

---

## 11. Report Parser Regression Test Suite UI

**Motivation:** Spec §16 says "collect real reports from varied senders for regression testing." A test-corpus management page keeps the corpus current and visible.

**Scope:**
- Admin+ UI: upload `.xml`/`.zip`/TLS-RPT `.json` samples, list them with last-test result, "re-parse all" against a dry-run ingestion path, diff view on regression.
- Corpus stored separately from live reports.

**Effort:** Medium. Needs a test-specific ingestion path + dry-run mode for parsing. Low priority — a plain `tests/fixtures/` directory exercised by PHPUnit gets most of the value without a UI.

---

## 13. SMTP TLS-RPT Forwarding (Proactive)

**Motivation:** Spec §12 handles TLS-RPT *reception*. A companion script to *send* your domain's TLS postmaster reports completes the symmetric picture.

**Scope:**
- `bin/submit-tls-rpt.php`: reconstruct RFC 8460 JSON from your own ingestion, submit to major providers' TLS postmaster mailboxes, track in `tls_rpt_submissions`.
- Config: enable per-domain via `domains.submit_tls_rpt`.

**Effort:** Medium-to-high. Low priority vs. receiving TLS-RPT — outbound TLS issues are less common. Phase 2+.

---

## 14. Dark Mode — Shipped 2026-08-12

**Motivation:** Minor UX polish; respect `prefers-color-scheme` and add a manual toggle.

**Built as:** a topbar toggle (`View::themeToggle()`) backed by `localStorage` (no DB migration, no per-user server round-trip — works identically on the public landing/help pages and the authenticated dashboard). `public/assets/theme-init.js` is a blocking `<head>` script that applies the stored choice before body paint (FOUC avoidance under the app's inline-script-free CSP); `public/assets/theme.js` wires the click handler and `aria-pressed`/`aria-label`. `app.css`'s existing `prefers-color-scheme` dark palette is preserved as the system-default fallback; an explicit choice (`data-theme="light"`/`"dark"` on `<html>`) overrides it. New `i-sun`/`i-moon` icons added to `public/assets/icons.svg`.

**Effort:** Low, as scoped. Commit `ba291c0`.

---

## 16. DNS Record Builder Wizards

**Motivation:** Guided, step-by-step tools to construct valid DNS records (SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT) without manual syntax errors.

**Overlap warning:** the SPF/DMARC portions of this duplicate **#9 (SPF/DKIM Configuration Snippet Generator)** — both are "parse current record → validate → suggest/build new record → copy to clipboard" against the same evidence. Don't build both from scratch; if pursued, build #9 first (it's remediation-triggered, smaller surface) and layer the from-scratch wizard UI on top only for record types #9 doesn't cover (BIMI, MTA-STS, TLS-RPT, and a from-scratch DMARC/SPF flow for domains with no health-check findings yet).

**Scope (condensed — see git history for the original full per-record-type step list):**
- SPF wizard: mechanism builder (include/ip4/ip6/a/mx/ptr/all), DNS-lookup-count validation, preview + copy.
- DMARC wizard: policy/subdomain-policy/pct/fo/rua/ruf/alignment fields, preview + copy.
- DKIM wizard: selector + key input/validation, preview + copy.
- BIMI/MTA-STS/TLS-RPT wizards: same preview-and-copy pattern, gated on those features existing first (BIMI isn't built at all yet — §10.7).
- Common: accessibility, inline help text, provider-suggestion dropdowns, no DB persistence (stateless, optional localStorage draft).

**Effort:** Medium-to-high. Multi-step form UI, record parsers/validators, provider dropdown data, accessibility testing.

**Priority:** Downgraded from the original "High for v1.2" — do #9 first and re-evaluate whether the full wizard UI is still worth it once remediation snippets exist.

---

## 17. Build-Wizard / First-Run Setup

**Motivation:** New deployments face friction: manually creating the database, running migrations, editing `config.php`, setting up IMAP accounts, and performing initial health checks.

> **⚠️ Security concern — read before picking this up.** The scope as originally written is a browser-based, **pre-login, unauthenticated** wizard that writes DB/IMAP/SMTP credentials into `config/config.php` from a web form, and is explicitly "not rate-limited during initial setup." That's a direct regression against every security decision already made elsewhere in this codebase: invitation-only account creation, mandatory MFA for every role, step-up re-verification (`StepUp`) for sensitive admin actions, and a strict CSP. An unauthenticated setup endpoint that accepts and persists credentials is new attack surface on a box that otherwise has none before first login — and it only saves the time of running `cp config.sample.php config/config.php` + `php bin/migrate.php` once per deployment, since this is a single self-hosted instance, not a product installed by strangers.
>
> If this is still wanted, the safe version is CLI-only (`bin/setup.php` prompting interactively, or a documented manual checklist) — not a network-exposed pre-auth form. A first admin account still needs invitation-flow semantics preserved (spec §15.2), not a bootstrap form that bypasses it.

**Scope (as originally proposed, kept for reference):** welcome step → DB connection test/auto-create → run migrations with progress → IMAP/SMTP/site config form → create first Super Admin → optional seed-domains load → summary. Setup-complete flag/lock file to prevent re-run; Super Admin "re-run setup" option for reconfiguration.

**Effort:** Medium for the UI as originally scoped; the CLI-only alternative is Low (wrap `bin/migrate.php` + interactive prompts, no new HTTP surface).

**Priority:** Downgraded from "High for v1.1" pending a decision on the CLI-only alternative above.

---

## Deferred — assume a deployment scale this instance doesn't have

These are reasonable ideas for a multi-tenant SaaS or a consulting/hosting-provider deployment managing dozens-to-hundreds of domains. This instance is a private, invitation-only tool for one team running ~10 domains. Kept here for reference in case that changes; not worth designing against today.

- **Batch Domain Onboarding / CSV Import** — bulk-importing 10–100 domains via CSV only pays off once one-at-a-time admin onboarding is actually a bottleneck. It isn't at 10 domains.
- **Multi-Domain Comparison / Cohort Analysis** — a sortable "domain portfolio" table largely duplicates what the overview dashboard already ships: a posture-card grid with health grade, 14-day sparkline, and open-recommendation-by-severity badges per domain (`DomainController::renderIndex()`, spec §7.1).
- **Database Backup / Restore UI** — running `mysqldump` from the web app and serving the tarball for download is more attack surface than a small internal deployment should take on for this. Belongs at the infra layer (cron + off-site backup), not in-app.
- **Performance Monitoring Dashboard** — a `performance_log` table, cron instrumentation, and time-series charts for a handful of daily cron jobs on one box. `journalctl`/cron logs already answer "did ingestion run and how long did it take" at this scale.
- **Rate-Limited / Staggered Onboarding & Health Checks** — explicitly motivated by "100+ domains" hammering DNS/DNSBL. Not a concern at 10.

---

## Decision Matrix: Priority & Effort

| Feature | Effort | User Impact | Suggested Phase |
|---------|--------|-------------|-----------------|
| Report filtering & export | M | High (forensics/compliance) | 1.1 |
| SPF/DKIM snippets | M | High (remediation speed) | 1.1 |
| Webhook alerting | M | High (ops integration) | 1.1–1.2 |
| Audit-log search | M | High (compliance/forensics) | 1.1–1.2 |
| REST API | M | Medium (integrations) | 1.2 |
| Policy dry-run | L–M | Medium (safer deployments) | 1.2 |
| Custom alerting rules | L | Medium (ops tuning) | 1.2 |
| ~~Dark mode~~ | L | Low (UX polish) | Shipped 2026-08-12 |
| DNS Record Builders | M–H | Medium (overlaps #9 — do #9 first) | 1.3, re-evaluate |
| Build-Wizard / First-Run Setup | M (UI) / L (CLI) | Medium | Re-scope to CLI-only before building |
| Parser test corpus | M | Low (development) | 1.3 |
| TLS-RPT forwarding | M–H | Low (niche) | 2.0+ |

---

## Recommendations for v1.1–v1.2

### v1.1 (Quick wins — deploy ASAP)
1. **Report filtering & export** — unblocks compliance workflows.
2. **SPF/DKIM configuration snippets** — directly extends R1/R2 evidence already computed; highest leverage per unit of effort.
3. **Webhook alerting** — plugs into existing team tooling (Slack, Teams) via the existing `AlertCheck` architecture.
4. **Audit-log search** — the viewer already exists; this is filters + an index, not a new subsystem.

### v1.2 (Medium effort, still worth it)
5. **REST API** — read-only, API-key-gated; scope down from "SOCs/ticketing systems" framing to what this team's own tooling actually needs.
6. **Policy dry-run** — safer policy changes.
7. **Custom alerting rules** — thresholds are already parameterized in `bin/alert.php`, just needs an admin UI.

~~8. Dark mode~~ — shipped 2026-08-12, see item #14.

### Needs a decision before scoping further
- **DNS Record Builders** — merge scope with SPF/DKIM snippets (#9) rather than building both.
- **Build-Wizard / First-Run Setup** — resolve the pre-auth security concern (CLI-only vs. web form) before writing any code.

### Not pursuing at current scale
See "Deferred" section above.

---

*This document is living; update as priorities and feedback evolve.*
