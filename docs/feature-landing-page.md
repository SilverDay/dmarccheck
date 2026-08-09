# Feature Spec — Public Landing Page

**Status:** Built 2026-08-09. `src/Http/Controllers/LandingController.php` renders the hero/about/capabilities/help-CTA sections; `public/index.php`'s `/` route dispatches to it (unauthenticated) or `DomainController::index()` (authenticated) via a closure, since `Router` has no path-param support to do this any other way. Two deviations: no `HELP_SYSTEM_ENABLED` fallback (§7 — the help system is live, so the link is unconditional) and no version/source link in the footer (§4.2 — this codebase has no version-tracking mechanism and is a private internal tool, not an attributed public project).  
**Relates to:** spec §7 (Dashboard), §15 (Auth/RBAC); feature-helpsystem.md

---

## 1. Overview

Today, `/` redirects unauthenticated visitors directly to the login screen. There is no public-facing page that explains what the tool is, who it is for, or where to find help. First-time invitees land on a bare login form with no context.

This feature adds a **public landing page** at `/` that:

- Explains what the tool does in plain language ("About").
- Lists its main capabilities at a glance.
- Links to the public help system (`/help`), so users can read DMARC 101 articles before or without logging in.
- Provides a clear call-to-action for authentication (sign in / accept invitation).
- Replaces the bare redirect without removing any existing auth flow.

The page is intentionally minimal — this is an internal security tool, not a marketing site. Its purpose is orientation and trust, not conversion.

---

## 2. Goals

- Give first-time invitees immediate context before they hit the login form.
- Surface the help system entry point publicly so DMARC 101 articles are accessible without an account.
- Make the tool self-describing: a new operator joining the team should understand what they're about to log into.
- Keep the page static and fast — no database queries, no auth dependency, no JS required.

---

## 3. Non-goals

- Marketing copy, feature comparisons, or promotional content.
- A public-registration or "request access" form (invitations remain the only account-creation path, per spec §15.2).
- Any personalisation or session-aware content on the landing page itself.
- A separate "public documentation site" — the help articles at `/help/<slug>` serve that purpose.

---

## 4. Page structure

### 4.1 Route

| Method | Path | Auth required | Controller |
|---|---|---|---|
| `GET` | `/` | No | `LandingController::show()` |

The existing `GET /` route (currently `$auth->guard(…, [$domainController, 'index'])`) is split:

- Unauthenticated visitors → `LandingController::show()` (new, public).
- Authenticated visitors → existing `DomainController::index()` (unchanged, redirect or direct).

The router checks session state and dispatches accordingly, or `LandingController::show()` detects an active session and issues a `302` to `/` (the dashboard) — whichever is a cleaner fit for the existing `Router`/`AuthMiddleware` pattern.

### 4.2 Layout sections

#### Hero

A single headline and one-sentence description. No animated elements.

```
DMARC Report Analyzer
Monitor email authentication, catch spoofing, and advance your domains
safely toward enforcement — all from one self-hosted dashboard.
```

One primary button: **Sign in →** (links to `/login`).  
One secondary link: **Read the DMARC 101 guide →** (links to `/help`).

#### About

Two to three short paragraphs (no bullet walls) explaining:

1. **What it does** — ingests DMARC aggregate reports from your mailbox, parses them, enriches source IPs, and surfaces pass/fail trends, unknown senders, and concrete recommendations per domain.
2. **Why it exists** — DMARC aggregate reports are the authoritative evidence base for understanding who is sending as your domain and whether authentication is working. This tool makes that data actionable without requiring manual XML parsing or a third-party SaaS.
3. **Who it's for** — operators running a handful of domains on their own infrastructure, who want visibility and a safe path toward `p=reject` without handing report data to an external service.

#### Capabilities summary

A compact grid (three columns on wide screens, one column on mobile) of feature cards. Each card has a short title and one sentence. No icons required; plain text cards are fine.

| Title | One-liner |
|---|---|
| Ingestion | Polls your DMARC mailbox automatically; tolerates vendor XML deviations and hostile input. |
| Enrichment | Labels source IPs as known infrastructure or unknown senders via rDNS, ASN, and your allowlist. |
| Recommendations | R1–R12 rule engine turns report data into prioritised, evidence-backed action items. |
| Health checks | Probes SPF, DKIM, DMARC, MX, DNSSEC, MTA-STS, TLS-RPT, blocklists, and more on demand. |
| Alerting | Daily digest flags heartbeat failures, policy drift, unknown-sender spikes, and pass-rate drops. |
| DMARC 101 | Built-in contextual help explains every term, finding, and recommendation — no external reference needed. |

#### Help system entry point

A distinct section (visually separated) linking to the help system:

```
New to DMARC?
The built-in DMARC 101 guide covers everything from SPF basics to
reading aggregate reports and understanding each recommendation rule.
No account required.

→ Browse the help articles
```

This section is the only content on the landing page that requires the help system to exist; it should degrade gracefully (hidden or replaced with a plain sentence) if `/help` is not yet implemented.

#### Footer

Minimal: tool name, version (from `config('app.version')` or a constant), and a link to the project source (optional, only if the deployment is intended to be attributed).

---

## 5. Implementation

### 5.1 Controller

```
src/Http/Controllers/LandingController.php
```

`LandingController::show(SessionManager $session): void`

- If `$session->current()` returns an active user, redirect `302` to `/domain` (the dashboard).
- Otherwise render `views/landing.php` via the existing `View` helper.
- No database queries. No config lookups beyond the app name/version constant.

### 5.2 View

```
src/Views/landing.php
```

Plain PHP template following the same pattern as existing views. Uses the existing page-shell helper for `<head>`, CSP headers, and `<footer>`. Body content is the four sections from §4.2.

### 5.3 Router change

In `public/index.php`, the existing root route:

```php
$router->get('/', $auth->guard(Roles::READ_ONLY, [$domainController, 'index']));
```

becomes two dispatches:

```php
$router->get('/', static function () use ($auth, $landingController, $domainController): void {
    if ($auth->currentUser() !== null) {
        $domainController->index();
    } else {
        $landingController->show();
    }
});
```

(Exact pattern follows the existing routing conventions in the file.)

### 5.4 Stylesheet

The landing page reuses the existing CSS custom properties and base stylesheet (`public/assets/app.css`). No new CSS file is needed for a minimal implementation. If the hero or capability grid requires layout rules that don't exist in the base sheet, add a `landing` modifier class with a `<style>` block in the view (as a `<link>` to a new `public/assets/landing.css` if the project ever adds a build step — for now inline in the view is fine since the CSP already allows page-owned styles).

### 5.5 No JavaScript required

The landing page is fully static HTML. The help-system JS (`public/js/help.js`) is not loaded here — tooltips and the help panel are dashboard features. The "Browse the help articles" link is a plain `<a href="/help">`.

---

## 6. Security considerations

- The landing page is **public** and must not leak any tenant data, domain names, user counts, or configuration.
- No session cookie is set on this page (cookies are set only on successful login, per the existing `AuthController`).
- All existing security headers (CSP, HSTS, X-Frame-Options, etc.) are applied by the bootstrap in `public/index.php` before any controller runs — no change needed.
- The page must not render any user-supplied input; it is entirely static authored content.

---

## 7. Help system integration

The landing page links to the help system's index at `/help`. That route is defined in `feature-helpsystem.md` as publicly accessible without authentication. The landing page does not depend on any other help-system feature (no tooltip JS, no inline article fetch) — the link alone is the integration point.

If `/help` is not yet implemented when the landing page ships, the help section (§4.2 "Help system entry point") renders a static paragraph instead of the link, controlled by a simple constant:

```php
define('HELP_SYSTEM_ENABLED', false); // flip to true when /help is live
```

---

## 8. Relationship to existing routes

| Route | Before | After |
|---|---|---|
| `GET /` (unauthenticated) | Redirects to `/login` via `auth->guard()` | Shows landing page |
| `GET /` (authenticated) | Shows domain dashboard | Shows domain dashboard (unchanged) |
| `GET /login` | Login form | Login form (unchanged) |
| `GET /help` | Not yet implemented | Public help index (feature-helpsystem.md) |

No existing authenticated route changes. No RBAC logic changes.

---

## 9. Future extensions (not v1)

- **System status panel**: show a "last ingestion" timestamp or a green/red pipeline indicator for operators who check the landing page as a quick health glance before logging in. Requires one lightweight DB query and a carefully scoped public read path — defer until the help system and landing page are stable.
- **Invitation acceptance shortcut**: if the visitor arrives with a valid `?token=` query parameter, skip the landing page and go directly to the invitation-acceptance flow (`/invite?token=…`). Currently a direct link in the invitation email works; this is a UX polish item.
- **Theming / branding**: allow the `app.name` config key to customise the headline and footer — useful if the tool is forked for a different organisation name.
