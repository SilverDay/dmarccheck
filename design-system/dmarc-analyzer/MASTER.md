# Design System Master File — DMARC Analyzer

> **LOGIC:** When building a specific page, first check `design-system/dmarc-analyzer/pages/[page-name].md`.
> If that file exists, its rules **override** this Master file. If not, follow the rules below.

**Category:** Internal security/admin dashboard (not a marketing site — no landing page, hero, or CTA patterns apply)
**Design Dials:** Variance 3/10 (Centered/Minimal) · Motion 3/10 (Subtle) · Density 8/10 (Dense/Dashboard)

**Note on generation:** the ui-ux-pro-max `--design-system` auto-search initially matched an "Exaggerated
Minimalism" / "Real-Time Operations Landing" pattern (oversized editorial type, hero-CTA structure) — that's
tuned for marketing landing pages, not a CRUD admin tool with data tables and forms. This file replaces that
output with a manual synthesis from three targeted domain searches instead: `--domain style "admin dashboard
data table enterprise"` → **Data-Dense Dashboard**, `--domain color "security enterprise trustworthy"` →
**B2B Service** palette (adapted), `--domain typography "admin dashboard professional neutral"` → **Minimal
Swiss** (Inter). This is the correct base for this app; treat it as authoritative over any future
`--design-system` re-run unless the app's nature changes.

---

## Why this direction

DMARC Analyzer is used by a small internal security team to read dense tabular data (domains, reports,
pass/fail rates, recommendations) and occasionally take consequential actions (change a user's role, remove
a passkey, reset MFA). The design has to:

1. **Get out of the way of the data.** Compact rows, minimal chrome, no decorative motion.
2. **Make severity legible at a glance.** DMARC has real semantic states (pass/quarantine/reject,
   known/unknown sender, health-check pass/warn/fail/error) — color + icon + text together, never color alone.
3. **Read as serious, not playful.** Navy/slate neutrals, a single restrained accent, sharp (not bubbly)
   corners, flat surfaces over heavy shadows.
4. **Work identically in light and dark**, since this is the kind of tool people leave open in a terminal-
   adjacent tab.

---

## Color Palette

### Light mode

| Role | Hex | CSS Variable | Usage |
|---|---|---|---|
| Background | `#F8FAFC` | `--color-bg` | Page background |
| Surface | `#FFFFFF` | `--color-surface` | Cards, table, panels |
| Surface Muted | `#F1F5F9` | `--color-surface-muted` | Table header row, zebra stripe, code blocks |
| Foreground | `#0F172A` | `--color-fg` | Primary text |
| Foreground Muted | `#64748B` | `--color-fg-muted` | Secondary text, labels, timestamps |
| Border | `#E2E8F0` | `--color-border` | Table/card borders, dividers |
| Primary | `#0F172A` | `--color-primary` | Nav bar, primary buttons, headings |
| Accent | `#0369A1` | `--color-accent` | Links, focus ring, active nav item, info |
| Accent Muted | `#E0F2FE` | `--color-accent-muted` | Selected row, info banner background |

### Dark mode

| Role | Hex | CSS Variable | Usage |
|---|---|---|---|
| Background | `#0B1220` | `--color-bg` | Page background |
| Surface | `#111A2E` | `--color-surface` | Cards, table, panels |
| Surface Muted | `#182238` | `--color-surface-muted` | Table header row, zebra stripe |
| Foreground | `#E2E8F0` | `--color-fg` | Primary text |
| Foreground Muted | `#94A3B8` | `--color-fg-muted` | Secondary text |
| Border | `#243149` | `--color-border` | Dividers |
| Primary | `#E2E8F0` | `--color-primary` | Headings (inverted from light) |
| Accent | `#38BDF8` | `--color-accent` | Links, focus ring, active nav |
| Accent Muted | `#0C2942` | `--color-accent-muted` | Selected row background |

### Semantic status (same intent both themes, tuned per background — DMARC-specific)

| State | Light | Dark | Used for |
|---|---|---|---|
| Success / Pass | `#16A34A` on `#F0FDF4` | `#4ADE80` on `#0F2A1A` | DKIM/SPF pass, health check pass, active user |
| Warning / Quarantine | `#B45309` on `#FFFBEB` | `#FBBF24` on `#2E2205` | Quarantine disposition, health check warn, invited (pending) |
| Danger / Reject | `#DC2626` on `#FEF2F2` | `#F87171` on `#2E1215` | Reject disposition, health check fail, destructive actions, disabled user |
| Neutral / Error-info | `#475569` on `#F1F5F9` | `#94A3B8` on `#182238` | Health check "error" (unresolvable — never render as pass) |
| Unknown sender | `#7C3AED` on `#F5F3FF` | `#A78BFA` on `#211B3D` | known vs unknown sender classification badge |

Every status is rendered as a **badge: icon + text label + color** — never a bare color dot (WCAG
color-not-only, and this app's own spec explicitly distinguishes "error" from "fail," which color alone can't
communicate).

---

## Typography

- **UI font (headings + body):** Inter — chosen over the auto-suggested Fira Sans/Fira Code pairing because a
  single neutral family reads calmer across a form-heavy, table-heavy app; Inter's tabular figures keep numeric
  table columns aligned.
- **Monospace (IPs, hashes, TOTP secrets, recovery codes, DKIM selectors):** JetBrains Mono — high
  x-height, disambiguated `0/O` and `1/l/I`, which matters directly for recovery-code and secret legibility.

```css
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
```

| Token | Size / Line-height | Weight | Usage |
|---|---|---|---|
| `--text-xs` | 12px / 16px | 400–500 | Table meta, timestamps, badges |
| `--text-sm` | 13px / 20px | 400–500 | Table body, form helper text |
| `--text-base` | 15px / 24px | 400 | Body text, form inputs |
| `--text-lg` | 18px / 28px | 600 | Card/section titles |
| `--text-xl` | 22px / 30px | 700 | Page titles (h1) |
| `--text-mono` | 13px / 20px | 400–500 | Secrets, IPs, hashes, codes (JetBrains Mono) |

Note the base is 15px, not the usual 16px minimum — deliberate for density on a data-heavy internal tool used
on desktop only (no mobile-zoom concern), but every table row stays ≥ 32px tall so click/scan targets remain
comfortable.

---

## Spacing (Density 8/10)

| Token | Value | Usage |
|---|---|---|
| `--space-xs` | 4px | Icon-to-label gap |
| `--space-sm` | 8px | Input padding-y, badge padding |
| `--space-md` | 12px | Table cell padding, form field gap |
| `--space-lg` | 16px | Card padding, section gap |
| `--space-xl` | 24px | Page margin, section separation |
| `--space-2xl` | 32px | Page top padding |

## Radius & Elevation

Flat, not glossy — 1px borders do the separating work, shadows are reserved for genuinely floating elements
(dropdowns, modals) so the page doesn't feel like a marketing site.

| Token | Value | Usage |
|---|---|---|
| `--radius-sm` | 6px | Inputs, buttons, badges |
| `--radius-md` | 8px | Cards, table container |
| `--radius-lg` | 12px | Modals |
| `--shadow-sm` | `0 1px 2px rgba(0,0,0,0.06)` | Sticky table header |
| `--shadow-md` | `0 4px 12px rgba(0,0,0,0.12)` | Dropdown menu, toast |
| `--shadow-lg` | `0 12px 32px rgba(0,0,0,0.18)` | Modal, dialog |

---

## Component Specs

### Buttons

```css
.btn-primary   { background: var(--color-primary); color: var(--color-bg); border-radius: var(--radius-sm);
                 padding: 8px 16px; font-weight: 600; font-size: var(--text-sm); }
.btn-secondary { background: transparent; color: var(--color-fg); border: 1px solid var(--color-border);
                 border-radius: var(--radius-sm); padding: 8px 16px; font-weight: 500; }
.btn-danger    { background: transparent; color: #DC2626; border: 1px solid #DC2626; }
/* all buttons: transition 150ms ease; cursor: pointer; disabled = opacity .5 + cursor: not-allowed */
```

### Stat tile (dashboard KPI card)

```css
.stat-tile { background: var(--color-surface); border: 1px solid var(--color-border);
             border-radius: var(--radius-md); padding: var(--space-lg); }
.stat-tile .value { font-size: 28px; font-weight: 700; font-variant-numeric: tabular-nums; }
.stat-tile .label { font-size: var(--text-xs); color: var(--color-fg-muted); text-transform: uppercase;
                     letter-spacing: 0.04em; }
```

### Table

```css
table { border-collapse: collapse; width: 100%; font-size: var(--text-sm); }
thead th { background: var(--color-surface-muted); position: sticky; top: 0; text-align: left;
           padding: var(--space-md); font-weight: 600; font-size: var(--text-xs); }
tbody td { padding: var(--space-md); border-bottom: 1px solid var(--color-border); }
tbody tr:hover { background: var(--color-surface-muted); }
/* numeric columns: font-variant-numeric: tabular-nums; text-align: right */
```

### Status badge

```css
.badge { display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; border-radius: 999px;
         font-size: var(--text-xs); font-weight: 600; }
/* background = status-bg, color = status-fg, plus a leading SVG icon — never color alone */
```

### Form input

```css
.input { padding: 8px 12px; border: 1px solid var(--color-border); border-radius: var(--radius-sm);
         background: var(--color-surface); color: var(--color-fg); font-size: var(--text-base); }
.input:focus { outline: none; border-color: var(--color-accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--color-accent) 25%, transparent); }
```

### Secret / code display (TOTP secret, recovery codes, IPs)

```css
.secret { font-family: 'JetBrains Mono', monospace; font-size: var(--text-mono); background: var(--color-surface-muted);
          padding: 2px 6px; border-radius: 4px; letter-spacing: 0.02em; }
```

---

## Icons

SVG only (inline or `<img>`), one consistent set — **Heroicons (outline, 20px, 1.5px stroke)**. No emoji
anywhere, including in status badges (a checkmark/warning-triangle/x-circle SVG, not ✅/⚠️/❌).

## Motion

Subtle only (dial 3/10) — this is a tool, not a showcase:

- Hover/focus transitions: 150ms ease, opacity/border-color/background only (no transform-based hover on
  table rows — it causes layout jitter at high density).
- Page/section reveals: none. Data should be visible immediately, not fade in.
- Toasts/flash messages: 200ms fade in, auto-dismiss 4s, respects `prefers-reduced-motion` (skip the fade,
  just show/hide).

## Anti-patterns for this app specifically

- ❌ Landing-page patterns (hero sections, big CTAs, marketing copy) — this is a tool, every screen is a
  destination reached by URL or nav, not a funnel.
- ❌ Oversized display type — reserve `--text-xl` (22px) as the largest text on any page.
- ❌ Color-only status (a red row with no icon/text) — every status needs icon + text + color together.
- ❌ Heavy shadows/glassmorphism/gradients — flat surfaces, 1px borders.
- ❌ Emoji icons anywhere, including in this codebase's existing plain-HTML pages.

## Pre-delivery checklist (from ui-ux-pro-max, applied to this app)

- [ ] Every status/severity indicator pairs icon + text + color (never color alone)
- [ ] Text contrast ≥ 4.5:1 in both light and dark (verify independently, not just light)
- [ ] Focus rings visible on every interactive element (keyboard nav is a real path for this audience)
- [ ] Tabular numeric columns use `font-variant-numeric: tabular-nums`
- [ ] No horizontal scroll on tables under 1024px — wrap in `overflow-x: auto`
- [ ] `prefers-reduced-motion` respected everywhere motion is used
- [ ] Secrets/codes rendered in the monospace token, never the UI sans font
