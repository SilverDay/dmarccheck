# TODO — Improvement Suggestions (from spec review)

Everything from the original review is built except the three items
below — all deliberately deferred, not forgotten. See
`docs/feature-helpsystem.md` (core built 2026-08-09; three sub-features
still open, listed as items 4-6 below) and `docs/feature-landing-page.md`
(built 2026-08-09) for the two larger features that came out of later
spec review. Nothing from either doc remains unstarted — items 4-6
below are the only open work left anywhere in this list.

### 1. Community Threat Reporting UI (spec §10.8)
The Spamhaus Threat Intel Community button is fully specified but ships disabled pending a T&C/GDPR review. Once that review is complete, build the UI: a per-finding "Report" button, a confirmation/review step, API submission, and an audit-log write.

### 2. `ruf` (Forensic Report) Ingestion (spec §1.2)
Explicitly a non-goal for v1 but not permanently out of scope. If forensic reports become relevant again (e.g. for specific reporters), the ingestion pipeline is ready to extend.

### 3. Chart.js / JSON Endpoint for Pass/Fail Trends (spec §7.2)
The spec calls for "Chart.js fed by a JSON endpoint" for the per-domain volume trend. Deliberately not done this way: the app has no JS dependency anywhere in the dashboard today, and the strict `default-src 'self'` CSP would require self-hosting any such library rather than pulling from a CDN. The current hand-rolled inline `SvgBarChart` avoids that dependency entirely. Revisit only if a self-hosted Chart.js build is worth the added maintenance surface for zoom/hover/toggle-series interactivity the SVG can't do.

### 4. Persistent per-page Help panel (feature-helpsystem.md §4.2)
A slide-in `<aside>` showing articles relevant to the current page, stays open while interacting with the main content. The tooltip mechanism (`?` icon + popover) and full `/help`/`/help/article` pages are built; this secondary entry point is not.

### 5. Onboarding guided summary (feature-helpsystem.md §4.5)
A one-time, dismissible walkthrough shown after a domain's first health check completes, explaining each finding in turn instead of a raw table.

### 6. Help search endpoint (feature-helpsystem.md §9)
`/help/search?q=` over article titles/summaries — explicitly listed as "not v1" in the doc itself; worth doing once the catalog grows past the current 85 articles.
