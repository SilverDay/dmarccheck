# TODO — Improvement Suggestions (from spec review)

## Phase 2 / Deferred features

### 1. TLS-RPT Ingestion (spec §12)
RFC 8460 JSON report ingestion is deferred but the pipeline scaffolding is in place. Adding a JSON parser alongside the XML one would give visibility into MTA-STS / STARTTLS failures that DMARC reports don't cover.

### 2. Community Threat Reporting UI (spec §10.8)
The Spamhaus Threat Intel Community button is fully specified but ships disabled pending a T&C/GDPR review. Once that review is complete, build the UI: a per-finding "Report" button, a confirmation/review step, API submission, and an audit-log write.

### 3. `ruf` (Forensic Report) Ingestion (spec §1.2)
Explicitly a non-goal for v1 but not permanently out of scope. If forensic reports become relevant again (e.g. for specific reporters), the ingestion pipeline is ready to extend.

---

## Dashboard / UI gaps

### 4. Chart.js / JSON Endpoint for Pass/Fail Trends (spec §7.2)
The spec calls for "Chart.js fed by a JSON endpoint" for the per-domain volume trend. The current implementation uses a hand-rolled inline SVG. A proper JSON endpoint + Chart.js would enable richer interactive drill-downs (zoom, hover, toggle series).

### 5. Attention Panel on Overview Dashboard (spec §7.1)
The spec describes an "Attention panel" showing the highest-severity open recommendations and recent High alerts across all domains. Build this so the first screen answers "what needs me today."

### 6. Ingestion Health Indicator on Overview Dashboard (spec §7.1)
Show last successful report ingestion time and last health-check run time on the overview page — surfaces a stalled pipeline immediately (ties to the heartbeat alert).

### 7. Recent Activity Feed on Overview Dashboard (spec §7.1)
Add a "Recent activity" section: newly seen unknown senders, policy changes detected, domains onboarded.

### 8. Allowlist Editor in the Dashboard (spec §10.5 / §15.1)
Admins can "edit allowlists" per the role table, but there is no UI for managing `known_senders` entries. Currently requires direct DB edits.

### 9. Onboarding Checklist — Cross-domain `rua` Authorization Record Generator (spec §11.2)
The health check verifies the cross-domain `_report._dmarc` TXT record exists, but the onboarding flow does not yet generate the exact record string for copy-paste. The spec explicitly requires this.

### 10. Audit Log Viewer in the Dashboard (spec §15.7)
The `audit_log` table is written to, but there is no Super Admin–only UI to read it. A log viewer would close the governance loop the spec emphasizes.

---

## Operational / cron gaps

### 11. Periodic Health-Check Scheduling (spec §11.5)
The spec allows health checks to be scheduled (e.g. weekly) but the default is onboarding + manual only. Add a `bin/healthcheck.php --all --scheduled` mode with a cron entry to turn the snapshot into ongoing drift detection.

### 12. Configurable Retention Policy (spec §14)
Section 14 calls for a "defined, justified retention" period for `report_records` / `ip_enrichment` rather than indefinite storage. Add a configurable retention cron (e.g. prune records older than N years) and a corresponding migration.

### 13. Per-sender Rate/Volume Caps on Ingestion (spec §4.1)
The spec lists per-sender rate/volume caps as a hardening control to prevent mailbox flooding / parser-DoS. This is noted but not yet implemented.

---

## Auth / security gaps

### 14. Breached Password List Check (spec §15.3)
NIST 800-63B requires checking new passwords against known-breached-password lists. Verify this is implemented (e.g. via the HaveIBeenPwned k-anonymity API) — not just Argon2 hashing.

### 15. Out-of-band Identity Re-verification Before Admin MFA Reset (spec §15.5)
The spec recommends requiring out-of-band identity re-verification before an admin clears a user's MFA factor, to prevent social-engineering bypass. Verify the current admin MFA-reset flow enforces this or at minimum presents a clear warning.
