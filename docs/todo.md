# TODO — Improvement Suggestions (from spec review)

Everything from the original review is built except the three items
below — all deliberately deferred, not forgotten. See
`docs/feature-helpsystem.md` and `docs/feature-landing-page.md` for two
larger proposed (not yet started) features that came out of later spec
review, tracked separately from this list.

### 1. Community Threat Reporting UI (spec §10.8)
The Spamhaus Threat Intel Community button is fully specified but ships disabled pending a T&C/GDPR review. Once that review is complete, build the UI: a per-finding "Report" button, a confirmation/review step, API submission, and an audit-log write.

### 2. `ruf` (Forensic Report) Ingestion (spec §1.2)
Explicitly a non-goal for v1 but not permanently out of scope. If forensic reports become relevant again (e.g. for specific reporters), the ingestion pipeline is ready to extend.

### 3. Chart.js / JSON Endpoint for Pass/Fail Trends (spec §7.2)
The spec calls for "Chart.js fed by a JSON endpoint" for the per-domain volume trend. Deliberately not done this way: the app has no JS dependency anywhere in the dashboard today, and the strict `default-src 'self'` CSP would require self-hosting any such library rather than pulling from a CDN. The current hand-rolled inline `SvgBarChart` avoids that dependency entirely. Revisit only if a self-hosted Chart.js build is worth the added maintenance surface for zoom/hover/toggle-series interactivity the SVG can't do.
