# Feature Enhancements — Beyond the Core Spec

**Status:** Backlog / post-v1 ideas  
**Scope:** Quality-of-life, operational excellence, and scaling improvements for larger deployments.

The core project is [feature-complete against the spec](../README.md#whats-implemented). This document captures ideas for incremental enhancements that would improve the tool for broader adoption or tier-down to smaller/solo operators.

---

## 1. REST API Endpoint Layer

**Motivation:** While the web UI is the primary interface, programmatic access enables integration with external tooling (Slack bots, custom monitoring dashboards, SOCs, external ticketing systems) without polling the UI.

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

## 2. Batch Domain Onboarding / CSV Import

**Motivation:** On-boarding 10–100 domains one-at-a-time through the UI is tedious. Consulting firms, hosting providers, and higher-education institutions need faster bulk setup.

**Scope:**
- CSV template: domain, target_policy (optional), non_sending (optional).
- Import form (Admin+ tier):
  - Validate CSV syntax, domain format.
  - Preview mode: show what will be created, domains already present.
  - Async job: run health checks in parallel (configurable concurrency to avoid DNS resolver hammering).
  - Progress bar + summary (N succeeded, N skipped, N failed + reason).
- **Idempotency:** re-importing the same CSV with a domain already present skips it gracefully.

**Example use case:**
```csv
domain,target_policy,non_sending
example.com,p=reject; sp=reject,0
internal.example.com,p=reject; sp=reject,1
old.example.com,,,1
```

**Effort:** Medium. Needs a job queue or async handler + progress tracking. Cron-friendly if done as a deferred CLI task.

---

## 3. Report Filtering, Search & Export

**Motivation:** The dashboard shows per-domain drill-down, but teams doing forensics or compliance audits often need "show me all unknown-source records from the last 30 days across all domains" and to export for external analysis or regulatory submission.

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

**Motivation:** `bin/alert.php` sends email only. Teams using Slack, Microsoft Teams, PagerDuty, or custom HTTP webhooks need real-time integration without polling email or RSS.

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

**Effort:** Medium. Requires HTTP client (Guzzle already in project?), retry logic, payload templating.

---

## 6. Multi-Domain Comparison / Cohort Analysis

**Motivation:** Portfolio-level oversight: "Which domains are weakest? Which have the most open recommendations? Who's still at p=none?"

**Scope:**
- New dashboard page (Admin+ tier): "Domain Portfolio Analysis."
  - Table: domain, policy, health-check grade, 14-day pass rate, open-recommendation count by severity.
  - Sortable/filterable by any column.
  - Heatmap-style color coding (green/yellow/red by policy strength and health grade).
  - Drill-down link to each domain's detail view.
- **Use case:** CTO's quarterly review, prioritizing which domains to harden next.

**Effort:** Low. Minimal new queries; mostly table + sorting logic.

---

## 7. Custom Alerting Rules Builder

**Motivation:** Thresholds are currently hardcoded: `unknown_ip_volume = 50`, `pass_rate_drop_pct = 10`. Teams want fine-grained control without editing `config.php`.

**Scope:**
- Super Admin UI: "Alerting Config" page (possibly part of a broader settings/admin panel).
  - Editable thresholds:
    - Unknown IP volume threshold (R5/R6 trigger).
    - Pass-rate drop % (detect regressions).
    - Heartbeat window (days without reports).
    - Policy-drift detection (always on, not tunable).
  - Per-domain overrides (optional): "Google Workspace: unknown IPs >100 before alert" vs. default 50.
  - Save to DB (`settings` table or extended `domains` columns).
- **Audit:** every threshold change is logged.

**Example use case:**
```
Domain receives high volume of reports from resellers (many unknown sources).
→ Set domain-specific unknown_ip_volume to 200 to reduce false positives.
```

**Effort:** Low. Mostly DB/UI work; logic already parameterized in `bin/alert.php`.

---

## 8. Audit Log Search & Visualization

**Motivation:** The audit-log viewer exists (Super Admin only) but is appendix-style. Security/compliance teams need to search and analyze the audit trail itself.

**Scope:**
- Enhanced audit-log UI:
  - Full-text search by action, actor email, affected domain.
  - Facets: action type (login, password change, policy edit, etc.), user, domain, date range, success/failure.
  - Time-series chart: login attempts over time, policy changes by week, etc.
  - Export audit log as CSV for compliance/SOC ingestion.
- **Performance:** add indexes on (actor_user_id, action, timestamp).

**Example use case:**
```
Investigator: "Show me all policy edits to production domains in the last 30 days."
→ Filter audit_log by action=domain_config_change, domains=[list], date range
→ See who changed what and when, with timestamp and detail_json
→ Export for compliance documentation
```

**Effort:** Medium. Requires query optimization + charting library (Chart.js already in project).

---

## 9. SPF / DKIM Configuration Snippet Generator

**Motivation:** Health check reports SPF/DKIM issues but doesn't output **ready-to-apply DNS records**. Reducing copy-paste friction speeds remediation.

**Scope:**
- Per-domain "Configuration Snippets" card (Admin+ tier):
  - **SPF:** For each R1 (known sender failing SPF):
    - Show current SPF record.
    - Suggest updated record with the sender's IP/CIDR/include added.
    - "Copy to clipboard" button.
    - Validation: does the new record exceed 10 DNS lookups? Warn if so.
  - **DKIM:** For R2 (known sender failing DKIM but passing SPF):
    - Explain which signing domain / selector needs enabling.
    - Link to the evidence (the source IP/domain from reports).
  - **DMARC:** Already generates `<policy>._report._dmarc.<destination>` record for cross-domain reporting (§7.2).
- **Scope note:** advisory only — tool never edits DNS.

**Example use case:**
```
R1: Mailchimp is failing SPF.
Tool shows:
  Current: v=spf1 include:sendgrid.net -all
  Suggested: v=spf1 include:sendgrid.net include:mailchimp.net -all
  Warning: new record has 8 DNS lookups (OK, under 10 limit)
  [Copy to clipboard]
```

**Effort:** Medium. Requires SPF parser (likely already in `HealthCheck` code), validation logic, templating.

---

## 10. Database Backup / Restore UI

**Motivation:** Currently a manual task for ops. A **backup scheduler + download** reduces friction for teams without shell access.

**Scope:**
- Super Admin UI: "Backups" page.
  - View recent backups (timestamp, size, status = success/failed/stale).
  - Download button for each backup (triggers a fresh backup or serves a pre-generated tarball).
  - Manual "Backup Now" button (async job).
  - Config: retention policy (keep last 7 daily backups, or tunable).
  - Integrity check: list table counts, hash of schema dump (simple sanity check on download).
- **Backup contents:**
  - `mysqldump` of the entire DB (or specific tables).
  - Optional: compress to `.tar.gz`.
  - Store in `archive/` or a dedicated `backups/` directory (outside web root).
- **Restore:** documented manual process (not automated, for safety).

**Example use case:**
```
Operator wants a Point-in-Time Recovery backup without SSH.
→ Go to Backups page → Download yesterday's backup
→ Restore locally for testing, or request DBA to restore to prod
```

**Effort:** Medium. Requires background job scheduling + file handling. Can start with a "trigger backup" button + cron-generated backups served via download link.

---

## 11. Report Parser Regression Test Suite UI

**Motivation:** Spec §16 says "collect real reports from varied senders for regression testing." A **test-corpus management page** keeps the corpus current and visible.

**Scope:**
- Admin+ UI: "Parser Test Corpus" (under Settings or Debug).
  - Upload form: drag-drop `.xml` or `.zip` DMARC reports (or `.json` TLS-RPT).
  - Corpus listing: filename, provider, upload date, last-test date, result (pass/parse error, if any).
  - "Re-parse all" button: runs `bin/ingest.php` in dry-run mode against the corpus, reports any regressions.
  - Diff view: if parsing result changed, show before/after (record counts, extracted fields).
- **Scope note:** corpus is stored separately from live reports (maybe `archive/test-corpus/` or a DB table).

**Example use case:**
```
Parser refactored to handle malformed records better.
→ Go to Parser Test Corpus → "Re-parse all" → confirm all test reports still parse
→ If a report that used to parse fails, flag it as a regression
```

**Effort:** Medium. Needs a test-specific ingestion path + dry-run mode for parsing.

---

## 12. Performance Monitoring Dashboard

**Motivation:** As deployments grow, ops need visibility into ingestion throughput, enrichment latency, and analysis runtime to spot bottlenecks.

**Scope:**
- Super Admin UI: "System Health" page (or merged into a settings/admin panel).
  - **Ingestion:** last run time, messages processed, messages failed, throughput (msgs/sec).
  - **Enrichment:** last run time, IPs processed, avg lookup time.
  - **Analysis:** last run time, domains analyzed, recommendations generated, avg time per domain.
  - **Health check:** last run time, domains checked, avg checks per domain, blocklist query timing.
  - **Alerting:** last run time, alerts sent, delivery status (email open rate if tracking, or just counts).
  - **Time-series charts:** ingestion throughput over last 7 days, analysis runtime trend, error rate.
  - **Heartbeat indicator:** cron job status (last execution within expected window?).
- **Logging:** each cron job logs execution time, record counts, errors to a dedicated `performance_log` table.

**Example use case:**
```
Operator: "Ingestion suddenly slowed down."
→ Go to System Health → see ingestion throughput dropped 50% yesterday at 2 PM
→ Check error rate spike → identify blocklist query hanging
→ Adjust timeout or disable that check temporarily
```

**Effort:** Medium. Requires performance-log table + cron instrumentation + charting.

---

## 13. SMTP TLS-RPT Forwarding (Proactive)

**Motivation:** Spec §12 handles TLS-RPT *reception*. A **companion script to *send* your domain's TLS postmaster reports** completes the symmetric picture.

**Scope:**
- New CLI script: `bin/submit-tls-rpt.php`.
  - Fetch TLS postmaster reports for your domains (from your own ingestion, aggregated).
  - Reconstruct RFC 8460 JSON.
  - Submit to major providers' TLS postmaster mailboxes (google-tls-rpt@, etc.) via SMTP.
  - Track submissions in a new table: `tls_rpt_submissions` (timestamp, domain, recipient, status).
- **Config:** enable per-domain via `domains.submit_tls_rpt` flag.
- **Scope note:** low priority vs. receiving TLS-RPT; outbound TLS issues are less common. Phase 2+.

**Effort:** Medium-to-high. Requires RFC 8460 report generation + SMTP submission logic. Worth defining after TLS-RPT reception is battle-tested.

---

## 14. Dark Mode

**Motivation:** Minor UX polish; respect `prefers-color-scheme` media query and add a manual toggle.

**Scope:**
- CSS: define dark-mode palette (backgrounds, text, borders, chart colors).
  - Reuse existing CSS variables if not already done.
  - Test against inline-SVG charts and icons (ensure contrast).
- UI: toggle in top-right corner (or under user settings).
- Storage: per-user preference in `users` table (or localStorage for unauthenticated help pages).

**Example:** `app.css` already minimal; adding `@media (prefers-color-scheme: dark) { ... }` + a few JS lines for manual toggle.

**Effort:** Low. Mostly CSS + minimal JS.

---

## 15. Rate-Limited / Staggered Onboarding & Health Checks for Large Deployments

**Motivation:** If you have 100+ domains, `bin/healthcheck.php` querying DNS/SMTP/DNSBL for all of them in parallel could hammer your resolver or trigger rate-limiting from Spamhaus DQS.

**Scope:**
- Config additions:
  ```php
  'healthcheck' => [
      'max_concurrent_checks' => 5,  // default 1 (sequential)
      'batch_delay_ms' => 500,       // delay between DNSBL queries per domain
  ],
  ```
- CLI: `bin/healthcheck.php --max-workers=5` to override config.
- Implementation: use `pcntl_fork()` (Unix only) or a queue-based async pattern (more portable but heavier).
- **Audit:** log concurrency decisions in performance log.

**Example use case:**
```
Onboarding 50 domains. Default sequential mode would take ~1 hour.
→ Set max_concurrent_checks=5 → reduces to ~10 minutes
→ Staggered DNSBL queries avoid rate-limiting
```

**Effort:** Medium-to-high. Process/concurrency management is complex; consider starting with config flags for batch delays instead of forking.

---

## 16. DNS Record Builder Wizards

**Motivation:** Users (especially non-technical domain admins) need **guided step-by-step tools to construct valid DNS records** (SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT) without manual syntax errors or security mistakes. Wizards complement the "Configuration Snippets" feature by enabling custom record creation from scratch, not just remediation of failing senders.

**Scope:**

### 16a. SPF Record Wizard (Admin+ tier)
- **Steps:**
  1. **Introduction:** Show current SPF record, explain what SPF does and common mechanisms.
  2. **Existing record analysis:** Parse and visualize current record (if exists). Show DNS lookup count.
  3. **Mechanism builder:** Add mechanisms one-by-one:
     - `include: <domain>` (e.g., for Google, Sendgrid, Mailchimp) — dropdown of known providers, or manual entry.
     - `ip4:/ip6: <cidr>` — IP/CIDR input with validation.
     - `a / mx / ptr` — checkboxes.
     - `~all` or `-all` — radio button.
  4. **Validation:** Real-time check:
     - DNS lookup count (warn if >10 or reaching the limit).
     - Syntax correctness.
     - Suggestion: combine multiple single `include` into one if possible (to reduce lookups).
  5. **Preview:** Show final record in plain text.
  6. **Copy to clipboard:** Copy `v=spf1 ... -all` to paste into DNS UI.

### 16b. DMARC Record Wizard (Admin+ tier)
- **Steps:**
  1. **Policy selection:** Radios for `p=none`, `p=quarantine`, `p=reject` with explanation of each.
  2. **Subdomain policy (sp):** Optional, same as `p`.
  3. **Percentage (pct):** Slider 0–100 (default 100).
  4. **Failure modes (fo):** Checkboxes for `0`, `1`, `d`, `s` (when to send aggregate reports).
  5. **Reporting addresses:**
     - **Aggregate reports (rua):** Input email(s) (can be external, e.g., Google, Agari).
     - **Forensic reports (ruf):** Input email(s), with warning about volume.
  6. **Alignment strictness:**
     - `adkim`: `r` (relaxed) or `s` (strict).
     - `aspf`: `r` or `s`.
  7. **Advanced (optional collapsible):**
     - `rf`: Report format (default `afrf`).
     - `ri`: Reporting interval (seconds; default 86400).
     - `aspf`/`adkim` sub-options (alignment mode).
  8. **Preview:** Show final `_dmarc.<domain>` TXT record.
  9. **Copy to clipboard + instructions:** Explain where to publish (DNS provider).

### 16c. DKIM Record Wizard (Admin+ tier)
- **Steps:**
  1. **Selector input:** User enters or selects from known email providers (Gmail's default `google`, Office 365's `selector1`/`selector2`, etc.).
  2. **Key format:** Radio for `RSA-2048` (default) or `RSA-1024` or `ED25519` (if supported).
  3. **Public key input:** Paste public key or generate placeholder (with link to provider docs).
  4. **Key validation:** Check format (PEM or base64).
  5. **Preview:** Show `<selector>._domainkey.<domain> TXT` record with formatted key.
  6. **Copy to clipboard + instructions:** Link to email provider's DKIM setup guide.

### 16d. BIMI Record Wizard (Admin+ tier, if #10.7 implemented)
- **Steps:**
  1. **Intro:** Explain BIMI (Brand Indicators for Message Identification) and requirements (DMARC p=reject, logo in .svg format).
  2. **Logo upload/URL:** Option to upload `.svg` or paste public URL.
  3. **Logo validation:** Check file size, format, SVG validity.
  4. **VMC (optional):** Input URL to Brand Registry or leave blank.
  5. **Preview:** Show `default._bimi.<domain> TXT` record.
  6. **Copy to clipboard.**

### 16e. MTA-STS Record Wizard (Admin+ tier, if MTA-STS delivery supported)
- **Steps:**
  1. **Intro:** Explain MTA-STS (SMTP TLS requirement policy).
  2. **Policy mode:** `testing`, `enforce`, or `none`.
  3. **Max age:** Slider, default 86400 (24h) or 31536000 (1 year).
  4. **Preview:** Show `.well-known/mta-sts.txt` policy and corresponding DNS TXT record `_mta-sts.<domain>`.
  5. **Copy + deployment instructions:** Warn about hosting `.well-known/mta-sts.txt` on HTTPS server.

### 16f. TLS-RPT Record Wizard (Admin+ tier)
- **Steps:**
  1. **Intro:** Explain TLS-RPT (TLS Report policy for delivery failures).
  2. **Reporting address:** Email input (rua field).
  3. **Mode:** `testing` or `aggregate`.
  4. **Preview:** Show `_tlsrpt.<domain> TXT` record.
  5. **Copy to clipboard.**

- **Common features across all wizards:**
  - **Accessibility:** Labels, keyboard navigation, ARIA hints.
  - **Help text:** Inline explanations of each field (collapsible "?").
  - **Example values:** Pre-populate with common patterns (e.g., "office365.com" for `include:` in SPF wizard).
  - **Validation feedback:** Real-time error messages (e.g., "Invalid IP address", "DNS lookups exceed limit").
  - **Copy-to-clipboard button:** Highlight the final record + copy button.
  - **Link to deployment docs:** After building, show "Next steps: How to deploy this record in your DNS provider" (DNS provider dropdown).
  - **Comparison view (optional):** Show "Current record vs. New record" side-by-side if updating.

- **Data persistence:**
  - Wizards are **stateless** (no database storage); users must manually deploy the record.
  - Optional: Save draft records in `LocalStorage` (client-side only) for convenience.

**Example user journey:**
```
Admin: "I need to publish DMARC for the first time."
→ Go to domain detail → click "DNS Record Builders" → choose "DMARC Wizard"
→ Step 1: Select `p=quarantine` (safest initial policy)
→ Step 2: Leave `sp` empty (applies to domain only)
→ Step 3: Set `pct=25` (test with 25% of mail, increase over time)
→ Step 4: Set rua email to internal abuse@
→ Step 5: Select `adkim=r`, `aspf=r` (relaxed, safer initially)
→ Step 6: Preview record: dmarc._dmarc.example.com IN TXT "v=DMARC1; p=quarantine; pct=25; adkim=r; aspf=r; rua=mailto:abuse@..."
→ Click "Copy to clipboard"
→ Go to DNS provider's web UI → paste record
→ Return to dmarccheck → health check runs, confirms record published
```

**Effort:** Medium-to-high. Requires:
- Multi-step form UI (reuse state machine from Build-Wizard if applicable).
- Record parsers/validators (SPF, DMARC syntax checking; likely already exists).
- Provider dropdown data (Google, Office 365, Sendgrid, etc. for `include:` suggestions).
- Accessibility testing.
- Deployment guide links (external; not hardcoded).

**Priority:** High for v1.2 (accelerates onboarding and improves accuracy). Can phase by record type (start with SPF + DMARC, add BIMI/MTA-STS/TLS-RPT in later phases).

---

## Decision Matrix: Priority & Effort

| Feature | Effort | User Impact | Suggested Phase |
|---------|--------|-------------|-----------------|
| REST API | M | High (integrations) | 1.1–1.2 |
| Batch onboarding | M | High (bulk setup) | 1.1 |
| Report filtering & export | M | High (forensics/compliance) | 1.1–1.2 |
| Policy dry-run | L–M | Medium (safer deployments) | 1.2 |
| Webhook alerting | M | High (ops integration) | 1.1–1.2 |
| Domain comparison | L | Medium (portfolio review) | 1.2 |
| Custom alerting rules | L | Medium (ops tuning) | 1.2 |
| Audit-log search | M | High (compliance/forensics) | 1.2 |
| SPF/DKIM snippets | M | High (remediation speed) | 1.2 |
| Backup/restore UI | M | Medium (ops safety) | 1.2–1.3 |
| Parser test corpus | M | Low (development) | 1.3 |
| Performance monitoring | M | Medium (scaling) | 1.2–1.3 |
| TLS-RPT forwarding | M–H | Low (niche) | 2.0+ |
| Dark mode | L | Low (UX polish) | 1.3 |
| Staggered health checks | M–H | Medium (large deployments) | 1.2–1.3 |
| DNS Record Builders | M–H | High (adoption/accuracy) | 1.2 |

---

## Recommendations for v1.1–v1.2

### v1.1 (Quick wins)
1. **Batch onboarding** — enables consulting/hosting use cases immediately.
2. **Report filtering & export** — unblocks compliance workflows.
3. **Webhook alerting** — plugs into existing team tooling (Slack, Teams).
4. **REST API** — enables external integrations + CLI tooling.

### v1.2 (High-value, medium effort)
5. **DNS Record Builders (SPF, DMARC)** — reduces configuration errors and accelerates initial deployment.
6. **Audit-log search** — compliance teams need it.
7. **SPF/DKIM snippets** — speeds remediation feedback loop.
8. **Policy dry-run** — safer policy changes.

### v1.3 (Nice-to-have / polish)
9. Custom alerting rules, domain comparison, backup UI, dark mode, performance monitoring.
10. **DNS Record Builders (advanced)** — add BIMI, MTA-STS, TLS-RPT wizards.

---

*This document is living; update as priorities and feedback evolve.*
