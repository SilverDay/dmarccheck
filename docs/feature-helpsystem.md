# Feature Spec — Contextual Help System ("DMARC 101")

**Status:** Core built 2026-08-09 (see `docs/todo.md` items 4-6 for what's still open: the persistent help panel §4.2, onboarding guided summary §4.5, and search §9). Built: the full 71-article catalog (§5) as `src/Help/content/*.php` + `HelpRepository`, `HelpController`'s public `/help`/`/help/article?slug=` index and article pages, the auth-gated `/help/inline?slug=` tooltip endpoint, and inline `?`-icon tooltips (§4.1/§6.2) wired into the domain drill-down's recommendation rule IDs, health-check badges, and source-table headers. One deviation from this doc: routes use `?slug=` query strings, not `/help/<slug>` path params — this app's `Router` is exact-string-match only (see CLAUDE.md), same reason `/domain` uses `?domain=`.  
**Relates to:** spec §7 (Dashboard), §9–§11 (findings, recommendations, health checks)

---

## 1. Overview

Users of this tool — even technically capable ones — frequently encounter DMARC jargon, auth-result codes, and recommendation IDs for the first time. Without inline explanations they must leave the tool and search externally, breaking their workflow and risking misinterpretation.

The help system provides **contextual, in-place explanations** for every term, finding, recommendation rule, health-check result, and dashboard widget. It functions as a built-in "DMARC 101" reference so users never need to leave the tool to understand what they are looking at.

---

## 2. Goals

- Explain any DMARC / email-authentication concept the tool surfaces, at the point it appears.
- Cover all recommendation rules (R1–R12), all health-check categories and result statuses, all alert types, dashboard metrics, and auth-result field values.
- Work for users with no prior DMARC knowledge ("what is `p=quarantine`?") and for experienced operators who need a quick reminder ("what exactly triggers R6?").
- Require zero external network access — all help content is bundled with the tool.
- Be maintainable: help content lives in structured data (PHP arrays or JSON), not scattered inline HTML strings.

---

## 3. Non-goals (v1)

- Video tutorials or animated walkthroughs.
- A separate "documentation site" or external wiki.
- Interactive wizards that change configuration (help is read-only / explanatory).
- Localization beyond English (can be added later given the structured-content approach).

---

## 4. Help entry points

Help is available at **every level** of the tool's UI. Each entry point uses the same underlying content store but is surfaced differently depending on context.

### 4.1 Inline tooltip (primary)

A `?` icon placed immediately after any jargon term, field label, status badge, metric name, or recommendation rule ID. Clicking (or keyboard-focusing) it opens a small popover with:

- A one-to-three sentence plain-English explanation.
- An optional "Learn more ↓" link that expands to the full article (§4.3) without navigation.

Examples of where tooltips appear:
- Field labels in the source table: `DKIM result`, `SPF result`, `Disposition`, `Alignment`, `header_from`.
- Auth-result values in report detail rows: `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`.
- Policy values anywhere: `p=none`, `p=quarantine`, `p=reject`, `pct=`, `sp=`, `adkim=`, `aspf=`.
- Recommendation rule IDs: `R1` … `R12` (each rule has its own tooltip).
- Health-check result statuses: `pass`, `warn`, `fail`, `error`, `info`.
- Health-check categories: `SPF`, `DMARC`, `DKIM`, `MX`, `DNSSEC`, `MTA-STS`, `TLS-RPT`, `BIMI`, `STARTTLS`, `DNSBL`, `RHSBL`, `FCrDNS`.
- Dashboard metric labels: "Pass rate", "Volume", "Unknown senders", "Policy drift", "Baseline".
- Alert type names in the alerting digest.

### 4.2 Help panel (secondary — per page)

A persistent `Help` button / link in the page header or sidebar that opens a **slide-in panel** showing articles relevant to the current page. The panel stays open while the user interacts with the main content, so they can read and act simultaneously.

- On the overview dashboard: general DMARC concepts, what the posture cards mean, how to read pass-rate sparklines.
- On the per-domain drill-down: source table interpretation, what the recommendation panel shows, how health-check grades are derived.
- On the recommendations panel: full rule catalog with trigger conditions and suggested actions.
- On the health-check results page: check-by-check explanations and what each status means operationally.
- On user/admin pages: invitation flow, MFA setup, session management.

### 4.3 Full-article view (tertiary)

Every tooltip's "Learn more" and every panel article links to a **full article page** at `/help/<slug>`. Articles follow a consistent structure:

1. **What it is** — plain-English definition.
2. **Why it matters** — practical consequence of a good or bad result.
3. **How to fix it / what to do** — concrete next steps (where applicable).
4. **Example** — a representative DNS record, report snippet, or scenario.
5. **References** — links to the relevant RFC or standard (RFC 7489 for DMARC, RFC 7208 for SPF, RFC 6376 for DKIM, RFC 8460 for TLS-RPT, etc.).

Articles are accessible without authentication — they contain no tenant data and blocking them behind login would prevent users from sharing a link to explain a concept.

### 4.4 Contextual help on recommendations (deep integration)

Each recommendation row in the dashboard has an inline `?` that opens an article specific to that rule. The article explains:

- The trigger condition in plain English (not just the rule table row).
- What the evidence snippet shown alongside it means.
- The concrete action to resolve it (e.g. "Add this SPF include token: `include:_spf.google.com`").
- Why *not* acting is risky (severity framing).
- How auto-resolution works — what change in the data will cause the recommendation to resolve itself.

### 4.5 Onboarding / first-run guidance

When a domain is first added and the initial health check completes, a **guided summary** panel explains each finding in turn rather than presenting a raw table. This is a one-time view (dismissible, re-openable via "Show onboarding guide") that walks through:

1. What the health check just measured.
2. What the current DMARC policy means.
3. What the "approve baseline" action does and why it matters.
4. The recommended next step given the health-check results.

---

## 5. Content catalog

All help content is keyed by a **slug** and stored in a single PHP file (or JSON) at `src/Help/content/`. The file returns an associative array of `slug → HelpArticle` objects. No content is hardcoded inline in templates.

### 5.1 DMARC fundamentals

| Slug | Topic |
|---|---|
| `dmarc-overview` | What DMARC is and how it works end-to-end |
| `dmarc-policy-none` | `p=none` — monitoring only; no enforcement |
| `dmarc-policy-quarantine` | `p=quarantine` — failing mail goes to spam |
| `dmarc-policy-reject` | `p=reject` — failing mail is discarded |
| `dmarc-pct` | `pct=` — gradual rollout percentage |
| `dmarc-sp` | `sp=` — subdomain policy |
| `dmarc-adkim` | `adkim=` — DKIM alignment mode (strict/relaxed) |
| `dmarc-aspf` | `aspf=` — SPF alignment mode (strict/relaxed) |
| `dmarc-rua` | `rua=` — aggregate report destination |
| `dmarc-alignment` | What "alignment" means and why it matters |
| `dmarc-aggregate-reports` | What aggregate reports contain and what they don't |
| `header-from` | What `header_from` is and why it's the alignment anchor |

### 5.2 SPF

| Slug | Topic |
|---|---|
| `spf-overview` | What SPF is and how it works |
| `spf-result-pass` | SPF `pass` |
| `spf-result-fail` | SPF `fail` |
| `spf-result-softfail` | SPF `softfail` — `~all` |
| `spf-result-neutral` | SPF `neutral` — `?all` |
| `spf-result-none` | SPF `none` — no record |
| `spf-result-temperror` | SPF `temperror` — transient DNS error |
| `spf-result-permerror` | SPF `permerror` — lookup limit exceeded or syntax error |
| `spf-lookup-limit` | The 10-DNS-lookup limit and how to fix it |
| `spf-all-qualifier` | The `all` qualifier: `-all`, `~all`, `?all`, `+all` |
| `spf-alignment` | SPF alignment: `MAIL FROM` vs `header_from` |

### 5.3 DKIM

| Slug | Topic |
|---|---|
| `dkim-overview` | What DKIM is and how signing works |
| `dkim-result-pass` | DKIM `pass` |
| `dkim-result-fail` | DKIM `fail` |
| `dkim-selector` | What a selector is and where to find it |
| `dkim-alignment` | DKIM alignment: signing domain vs `header_from` |
| `dkim-not-enumerable` | Why the health check can't guarantee full DKIM coverage |

### 5.4 Health-check results

| Slug | Topic |
|---|---|
| `hc-status-pass` | What `pass` means in a health-check result |
| `hc-status-warn` | What `warn` means |
| `hc-status-fail` | What `fail` means |
| `hc-status-error` | What `error` means — unknown, not clean |
| `hc-status-info` | What `info` means — informational, no action required |
| `hc-mx` | MX records: presence, resolution, reachability |
| `hc-dnssec` | DNSSEC: what it is, why absence is a posture signal |
| `hc-mta-sts` | MTA-STS: enforcing TLS on inbound mail |
| `hc-tls-rpt` | TLS-RPT: reporting transport security failures |
| `hc-bimi` | BIMI: brand logo in email clients |
| `hc-starttls` | STARTTLS and certificate validation |
| `hc-dnsbl` | IP-based DNS blocklists (DNSBL / Spamhaus ZEN) |
| `hc-rhsbl` | Domain-based blocklists (RHSBL / Spamhaus DBL) |
| `hc-fcrdns` | Forward-confirmed rDNS (FCrDNS) |
| `hc-report-auth` | Cross-domain `rua` authorization records |

### 5.5 Recommendation rules

One article per rule. Each covers: trigger, evidence, action, auto-resolution condition.

| Slug | Rule |
|---|---|
| `rule-r1` | R1 — Known sender, SPF fail, DKIM pass |
| `rule-r2` | R2 — Known sender, DKIM fail, SPF pass |
| `rule-r3` | R3 — Known sender, alignment failure |
| `rule-r4` | R4 — SPF lookup limit exceeded |
| `rule-r5` | R5 — Unknown source, failing auth, above threshold |
| `rule-r6` | R6 — Unknown source, sustained spoofing campaign |
| `rule-r7` | R7 — Safe to advance policy to `quarantine` |
| `rule-r8` | R8 — Safe to advance policy to `reject` |
| `rule-r9` | R9 — DNS policy drift / tamper detected |
| `rule-r10` | R10 — Non-sending domain with observed traffic |
| `rule-r11` | R11 — `sp` unset while subdomain spoofing observed |
| `rule-r12` | R12 — Forwarding-pattern failures (informational) |

### 5.6 Alerting

| Slug | Topic |
|---|---|
| `alert-heartbeat` | Heartbeat alert — no reports received for N days |
| `alert-policy-drift` | Policy drift alert — live DNS differs from baseline |
| `alert-unknown-volume` | Unknown-volume alert — spike from unknown sources |
| `alert-pass-rate` | Pass-rate regression alert |

### 5.7 Domain policy concepts

| Slug | Topic |
|---|---|
| `policy-current-published` | `current_published_policy` — what was read from DNS |
| `policy-approved-baseline` | `approved_baseline_policy` — your known-good state |
| `policy-target` | `target_policy` — where you want to get to |
| `policy-approve-baseline-action` | Why approving the baseline is a deliberate action |
| `non-sending-domain` | Non-sending domain flag and why to use it |

### 5.8 General / operational

| Slug | Topic |
|---|---|
| `known-vs-unknown` | Known vs. unknown sender classification |
| `enrichment` | IP enrichment: rDNS, ASN, labeling |
| `known-senders-allowlist` | The known senders allowlist and how to manage it |
| `ingestion-pipeline` | How reports flow from mailbox to dashboard |
| `report-dedup` | How duplicate report ingestion is prevented |
| `decompression-bomb` | What a decompression bomb is (hostile input hardening) |

---

## 6. Implementation

### 6.1 Content storage

```
src/Help/
    HelpArticle.php          // value object: slug, title, summary, body (HTML), references[]
    HelpRepository.php       // loads and looks up articles by slug
    content/
        dmarc.php            // returns array of HelpArticle for §5.1
        spf.php              // §5.2
        dkim.php             // §5.3
        healthcheck.php      // §5.4
        rules.php            // §5.5
        alerting.php         // §5.6
        policy.php           // §5.7
        general.php          // §5.8
```

`HelpRepository::get(string $slug): ?HelpArticle` is the single lookup point used by both the tooltip renderer and the full-article controller.

### 6.2 Tooltip rendering

A PHP helper `helpTooltip(string $slug, string $label = '?'): string` outputs:

```html
<button class="help-trigger" data-help-slug="example-slug" aria-label="Help: DKIM alignment">?</button>
```

A single small JS snippet (no external dependency, no framework) handles all tooltip popovers:

- Listens for clicks on `.help-trigger` buttons.
- Fetches `/help/inline/<slug>` (returns a JSON `{ summary, moreUrl }`) via `fetch()`.
- Renders a popover anchored to the button; closes on Escape or outside-click.
- Keyboard accessible: focus trap within the popover, `aria-expanded` on the trigger.

The inline endpoint `/help/inline/<slug>` requires authentication (like the rest of the dashboard) and returns only the `summary` field — keeping responses small.

### 6.3 Help panel

- Opened by a `Help` button in the page `<header>`.
- Rendered as a `<aside role="complementary" aria-label="Help">` sliding in from the right.
- The current page's slug list is passed from the controller via a PHP variable (e.g. `$helpPanelSlugs = ['dmarc-overview', 'hc-status-pass', ...]`).
- The panel fetches and renders those articles in order; each is an expandable `<details>` block.
- No separate JS route needed — panel content is rendered server-side into the page and hidden until the button is clicked (no fetch round-trip for the panel).

### 6.4 Full-article pages

Route: `GET /help/<slug>` → `HelpController::show(string $slug)`

- Accessible without authentication.
- Renders the full `HelpArticle` body (trusted HTML, authored content — not user input).
- Navigation: breadcrumb back to the dashboard, previous/next article within the same category.
- `<link rel="canonical">` so search engines can index the help content if the instance is public-facing.

### 6.5 CSP compatibility

The tool's current `default-src 'self'` CSP means:
- No inline `onclick=`; all JS is in a separate bundled file (`public/js/help.js`).
- The `fetch()` in `help.js` calls same-origin endpoints only — no CSP exception needed.
- No external CDN dependencies.

---

## 7. Accessibility

- Every `?` trigger is a `<button>` (not a `<span>` or `<a>`), keyboard focusable, with a descriptive `aria-label`.
- Popovers use `role="tooltip"` and are linked to the trigger via `aria-describedby`.
- The help panel uses `role="complementary"` and a visible close button with `aria-label="Close help panel"`.
- All content meets WCAG 2.1 AA contrast requirements (inherits from the existing dashboard CSS).
- Full-article pages are plain, semantic HTML — readable without JS.

---

## 8. Content style guide

Help articles follow these conventions to stay consistent and scannable:

- **Plain English first**: define the term before using it. Assume the reader knows email but not DMARC.
- **One concept per article**: if an explanation requires another concept, link to it rather than explaining it inline.
- **Concrete examples**: every article that can show a DNS record, report snippet, or configuration example should.
- **Action-oriented**: the "What to do" section uses imperative mood ("Add the following token to your SPF record:").
- **No marketing language**: no "powerful", "easy", or "seamless". Factual and direct.
- **RFC references**: cite the standard by number and section where relevant (e.g. "RFC 7489 §6.3").

---

## 9. Future extensions (not v1)

- **Search**: a `/help/search?q=` endpoint over article titles and summaries — useful once the catalog grows.
- **Localization**: the structured `HelpArticle` objects are translation-ready; the content PHP files can be swapped for locale-specific versions.
- **User feedback**: a "Was this helpful? Yes / No" micro-survey per article, writing to a `help_feedback` table — helps prioritize content improvements.
- **Wizard mode**: for onboarding, a step-by-step guided flow that combines help text with the actual configuration actions (goes beyond read-only help).
