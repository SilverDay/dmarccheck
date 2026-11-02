# Implementation Plan — Remaining and Proposed Work

This plan distinguishes required completion from optional post-v1 proposals.
The original analyzer spec is feature-complete except for the gated
community-threat-reporting item. The landing page and help-system features
are implemented. No post-v1 proposal is a commitment until its operator
need is confirmed.

## Phase 0 — Confirm scope and standards

Do this before changing DMARC behavior or persisting new standards fields.

- [x] Read the relevant RFC 9989/9990 sections and record the verified
  requirements for the tree walk, PSD/tag behavior, deprecated tags,
  optional report fields, and enforcement guidance.
- [x] Compare verified requirements with the implemented behavior and this
  plan; mark already-satisfied items rather than duplicating implementation.
- [x] Decide whether the goal is complete DMARCbis conformance or a
  narrower implementation of the explicitly described D1–D7 callouts.
- [x] Record any unresolved RFC interpretation as a decision; do not infer
  behavior from the feature proposal alone.

**Verification record (RFC 9989/9990):**
- RFC 9989 §4.10's tree walk, eight-query cap, `psd=y`/`psd=n` stopping
  behavior, and candidate selection match the existing `OrgDomain` flow.
  The tree walk must consider a policy record valid only when it has a valid
  `p=` value; that guard is now explicit.
- RFC 9989 §4.7's new policy tags are `np=` and `t=`; `psd=` is covered by
  D7. `t=y` requests test handling with an expected one-level-less strict
  policy; it is not a percentage-based replacement for `pct=`.
- RFC 9989 §3.2.9 defines Enforcement as a policy other than `p=none`.
  The RFC does not declare `p=reject` a universal target or make
  `p=quarantine` non-enforcing. Keep the existing configurable
  `target_policy` default from the original analyzer spec; do not claim the
  default is mandated by DMARCbis.
- RFC 9989 removes `pct=`, `rf=`, and `ri=` from its defined tag set.
  RFC 9990 §3.1.1.5 includes `discovery_method`, `np`, and `testing` in
  `policy_published`; it does not include `psd`. RFC 9990 §3.1.1.9 and
  §3.1.1.14 define per-record override reasons, including
  `policy_test_mode` as a `reason/type`, not a top-level report field.
- Scope decision: implement the specified D1–D7 integration, not every
  possible RFC 9989/9990 conformance requirement. Classic-vs-current
  behavior is shown only for the documented divergence points.

## Phase 1 — Complete the DMARCbis implementation

See [`feature-dmarcbis.md`](feature-dmarcbis.md). Current implementation
already includes organizational-domain tree-walk discovery, `pct=` handling,
some RFC 9990 report-field capture, a per-domain readiness section, an
overview attention indicator, and related help content.

1. **Parser and persistence**
   - [x] Capture the applicable RFC 9990 fields: `generator`,
     `discovery_method`, `envelope_from`, `envelope_to`, and per-record
     override reasons including `policy_test_mode`.
   - [x] Add a forward-only migration for policy override reasons.
   - [x] Add parser tests for present/absent override reasons; classic reports
     remain valid.
   - [x] Add opt-in DB-backed storage and migration tests for the new reason
     column (`tests/Integration/ReportStoreDmarcbisMigrationTest.php`).
2. **Health-check and readiness behavior**
   - [x] Complete the verified D1–D7 readiness behavior: deprecated tags are
     advisory, `pct<100` removal is guarded, inherited coverage is explicit,
     and invalid `np=`/`psd=`/`t=` values are surfaced for review.
   - [x] Keep inability to determine a result distinct from confirmed
     failure in the readiness card; include failed/unknown domains and
     deprecated-tag findings in the overview attention count.
   - [x] Add focused readiness rendering and overview-count tests for own
     policy, inherited coverage, uncovered/error results, deprecated/current
     tags, latest-run selection, and JSON-null handling.
   - [ ] Continue health-check behavior coverage across D1–D7 combinations.
3. **Recommendations and policy guidance**
   - [x] Re-check R7/R8 and target-policy guidance against the RFC. The rules
     remain policy-level, human-reviewed recommendations; `t=y` is not a
     fractional rollout replacement, quarantine is a valid Enforcement
     policy, and the per-domain configurable target default remains an app
     choice from the original spec rather than an RFC mandate.
   - [x] Keep recommendations advisory and leave DNS changes to operators.
   - [x] Add tests for policy levels, `t=`/`pct=` distinctions, and unchanged
     policy progression when the standards do not diverge.
4. **Presentation and help**
   - [x] Show classic-vs-current differences only where conclusions diverge,
     using linked callouts rather than duplicating every result.
   - [x] Link each readiness item to contextual help and update the
     DMARCbis articles, page help, and README status.
   - [x] Add catalog-completeness and presentation tests for readiness
     details, including classic-vs-current callouts.

**Exit criteria:** verified D1–D7 scope is implemented or explicitly
excluded with rationale; migrations, parser, health-check, recommendation,
dashboard, and help tests pass; no duplicate classic/current results where
the standards agree.

## Phase 2 — Select and deliver high-value operator enhancements

The order below follows `feature-enhancements.md`'s suggested v1.1 sequence.
Confirm the use case and exact filters/outputs before starting each feature.
These are separate deliverables and may be reprioritized independently.

1. **Report filtering, search, and export**
   - [x] Define filters (7/30/90 days or custom up to 366 days; label,
     DKIM/SPF, disposition, ASN organization), access (Read Only one domain;
     Admin/Super Admin may search all), CSV columns, 200-row page display,
     and 10,000-row export cap.
   - [x] Implement parameterized report-record search with server-side role
     enforcement and a date index for cross-domain range queries.
   - [x] Add the search UI, formula-safe CSV, and focused criteria/export
     tests; DB query/migration tests are opt-in via the isolated test DSN.
2. **SPF/DKIM remediation snippets**
   - [x] Define safe inputs and evidence: current R1/R2 recommendation
     subjects, report-observed SPF identities and DKIM domain/selectors, and
     live DNS TXT answers for valid targets.
   - [x] Add Admin-only advisory guidance and approximate SPF lookup counts;
     do not infer provider includes/IP mechanisms or publish DNS.
   - [x] Test DNS target validation, the shared SPF lookup counter, and
     report-evidence mapping. Empty DNS answers remain inconclusive, and
     lookup targets/results are bounded.
3. **Webhook alerting**
   - [x] Define generic HTTPS JSON destinations, environment-backed URL and
     HMAC-secret configuration, minimal payload, and nonblocking failure
     policy.
   - [x] Implement bounded timeouts/retries, request signing, redirect
     refusal, and audit outcomes without blocking email delivery.
   - [x] Test success, retry, permanent failure, secret redaction, and
     repeat-while-active behavior. Persistent cross-run deduplication is
     intentionally not used, matching the email digest.
4. **Audit-log search**
   - [ ] Define searchable fields/facets and date-range bounds.
   - [ ] Add parameterized queries and indexes based on query plans; preserve
     Super Admin authorization and append-only audit semantics.
   - [ ] Add filters, an SVG-based trend view if still needed, and CSV export;
     test access, filtering, and export escaping.

## Phase 3 — Integrations and operational controls

Proceed only where the operator has a concrete integration or control need.

- [ ] **Read-only REST API:** specify consumers and response schemas first;
  then add versioned endpoints, API-key lifecycle/storage, rate limits,
  authorization tests, and endpoint documentation.
- [ ] **Policy simulation:** define exactly what historical records can
  and cannot predict; implement a non-mutating policy override and impact
  summary; test that no database policy or DNS state changes.
- [ ] **Custom alert thresholds:** decide global-only versus per-domain
  values, define safe bounds, then add audited Super Admin controls and
  tests proving the CLI and UI use the same effective configuration.

## Phase 4 — Reassess niche or higher-cost proposals

Do not schedule these until the need and operational owner are clear.

- [ ] **Parser regression-corpus UI:** if needed beyond the existing PHPUnit
  fixture corpus, design isolated sample storage and dry-run parsing before
  implementing upload, re-parse, and diff UI.
- [ ] **TLS-RPT forwarding:** first establish recipient coverage, consent,
  delivery/retry semantics, and reporting value; then separately design
  storage and submission behavior.
- [ ] **DNS record builders:** evaluate after SPF/DKIM snippets ship; build
  only record types and workflows not already covered by snippets.
- [ ] **First-run setup:** decide whether a CLI helper is worthwhile. Do not
  build an unauthenticated web setup that accepts or writes credentials or
  bypasses invitation/MFA controls.

## External approval gate — community threat reporting

This is the only unbuilt item from the original analyzer spec (§10.8).
Implementation is blocked until the operator records the required review.

- [ ] Complete the Spamhaus terms-of-service and T&C/GDPR assessment,
  including lawful basis, data minimization, and third-party transfer.
- [ ] After approval only, implement the disabled-by-default feature gate,
  qualifying-finding rules, human review/confirmation, protected API
  credentials, manual submission, and audit logging of actor, indicator,
  evidence snapshot, and outcome.
- [ ] Test that ineligible findings and disabled configuration cannot
  submit, and that failures are surfaced and audit-recorded appropriately.

## Deferred unless requirements change

- **`ruf` forensic-report ingestion:** v1 non-goal because forensic reports
  can contain message-level personal data. Reconsider only with a specific
  use case and data-protection review.
- **Chart.js trend endpoint:** retain the current dependency-free SVG unless
  zoom/hover/series interactions justify the added dependency.
- **Scale-oriented UI:** batch onboarding, cohort comparisons, in-app
  performance dashboards, and staggered/rate-limited health checks are
  deferred for the current small deployment; reassess if scale grows.
- **Database backup/restore UI:** keep backups and restores at the
  infrastructure layer.

## Delivery discipline

For each selected feature: write acceptance criteria, add focused tests,
implement the smallest vertical slice, run the focused PHPUnit tests,
PHPStan, and PHP CS Fixer, then update the relevant feature document and
README status before marking its checklist item complete. Keep schema
changes in new numbered migrations; never edit a committed migration.
