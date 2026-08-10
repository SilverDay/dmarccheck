# Feature — DMARCbis Support (RFC 9989 / 9990 / 9991)

**Status:** added-feature design, separate from the shipped spec. The main
spec (`dmarc-report-analyzer-spec.md`) stays as-is; this file describes an
additive capability layered on top. Nothing here obsoletes the spec — it
extends it.

**Background:** in May 2026 the IETF published RFC 9989 (core), RFC 9990
(aggregate reporting) and RFC 9991 (failure reporting), which obsolete the
original RFC 7489 (2015) and move DMARC from Informational to a Proposed
Standard. The working-group nickname "DMARCbis" now just means current DMARC.
Records still begin `v=DMARC1`; most deployments keep working unchanged, so
this is an evolution to surface, not a rewrite.

---

## 1. Design principle — diff view over a single current engine

The tempting framing is "run classic-DMARC analysis and DMARCbis analysis in
parallel." That's the right *presentation* but the wrong *architecture*.
Two full evaluation engines is a permanent maintenance tax; the divergence
points between the two standards are few and enumerable, so we don't need it.

**The chosen shape:**

- **One evaluation core, DMARCbis-current (RFC 9989) as source of truth** —
  because that's the direction deployment is moving, and we don't want two
  engines drifting apart.
- **A "classic DMARC vs DMARCbis" diff *view* layered on top.** Where the two
  standards would reach a *different* conclusion for a given domain, surface
  both explicitly. Where they agree — the large majority of findings — show
  one unified result, no redundant "both agree" badge on every row.

The craft is: **one answer where the standards agree, two only where they
diverge**, with divergences clearly labelled as a DMARCbis change. This
delivers the parallel value the user wants (clarity about the transition)
without the parallel cost (a doubled, noisier dashboard).

The divergence set is bounded (see §2), so the diff view is a fixed list of
specific callouts, not a wholesale doubling of the analysis.

---

## 2. The divergence points (the whole surface area)

These are the only places the two standards materially differ for this tool.
Everything else (`v=DMARC1`; the `p`, `sp`, `rua`, `ruf`, `adkim`, `aspf`,
`fo` tags) is unchanged and needs no parallel treatment.

| # | Change under DMARCbis | Classic (RFC 7489) | DMARCbis (RFC 9989/9990) | Where it hits this tool |
|---|---|---|---|---|
| D1 | **Org-domain discovery** | Public Suffix List (PSL) | DNS **Tree Walk** (climb labels looking for a DMARC record) | Health check (org-domain + subdomain policy logic); any R-rule using the org domain |
| D2 | **`pct=` deprecated** | Valid; used for staged rollout | Deprecated — remove at next DNS edit | Recommendation engine R7/R8 (staged enforcement) |
| D3 | **`rf=` and `ri=` deprecated** | Valid | Deprecated | Parser tolerance; policy-record health check |
| D4 | **`p=reject` guidance flipped** | Reject as the assumed end goal | More nuanced guidance (verify against RFC 9989 text) | Recommendation engine target-policy logic; `target_policy` default |
| D5 | **New aggregate-report fields** | Absent | Optional `discovery_method`, `policy_test_mode`, `generator`, `envelope_from` (RFC 9990) | Parser (§5) — additive capture |
| D6 | **New policy tags** | Absent | New optional tags per RFC 9989 (verify the exact set against the RFC before implementing) | Parser; policy-record health check; help text |
| D7 | **PSD tag (`psd=`)** | Added later by RFC 9091 | Folded into RFC 9989 | Parser; org-domain logic |

**Every "verify against RFC 7489 §7.1" note in the main spec should now read
RFC 9989/9990** — in particular the report-authorization record (spec §11.2)
and the org-domain logic want re-checking against the new text, since the
tree walk (D1) changes how the organizational domain is determined.

> Build-time verification (do not hardcode from memory): the exact new-tag
> set (D6), the precise tree-walk algorithm (D1), and the revised `p=reject`
> guidance wording (D4) must be read from RFC 9989/9990 directly. The table
> above is the map, not the authoritative text.

---

## 3. Integration per subsystem

### 3.1 Parser (§5) — additive, no parallelism
- Capture the new optional RFC 9990 fields (D5) when present; `envelope_from`
  is the most analytically useful. Absence is normal (classic reporters omit
  them) — the existing tolerant design already ignores unknown elements, so
  this is purely "start reading fields we currently drop."
- Recognise (don't reject) the deprecated `rf=`/`ri=` and any new tags.
- No classic/bis branching here — the parser reads whatever a report contains.

### 3.2 Health check (§11) — where the parallel view leads
This is the best home for the explicit "classic vs DMARCbis" framing, because
it already emits per-check pass/warn/fail rows and the divergences are
concrete and actionable here.
- Add a **regime dimension** to the checks that differ (org-domain discovery
  D1, policy-record validity D3/D6). A check can report e.g.
  "valid under classic DMARC; the `pct=` tag is deprecated under DMARCbis."
- Add a dedicated **"DMARCbis readiness"** grouping: for each domain, the set
  of D1–D7 items that need attention to be cleanly RFC 9989-compliant. This
  is the migration-guidance feature — it turns the standards transition into
  a concrete per-domain checklist, which is on-brand for a guided-remediation
  tool.
- Checks that don't diverge stay single-valued (no regime column).

### 3.3 Recommendation engine (§10) — single core, flagged divergences
- Evaluate rules under DMARCbis as the source of truth.
- Rules whose *conclusion depends on the regime* carry a "differs under
  classic DMARC" flag rather than forking the engine:
  - **R7/R8** (staged enforcement) — currently lean on `pct=` (D2). Under
    DMARCbis, staged rollout is expressed differently; the recommendation
    text must change, and the rule notes that `pct=` is deprecated.
  - **Target-policy rules** — the flipped `p=reject` guidance (D4) affects
    whether `p=reject; sp=reject` remains the universal recommended target.
    Re-derive the default `target_policy` guidance against RFC 9989 before
    the engine keeps steering every domain to reject.
  - Any rule using the **org domain** — now via tree walk (D1), not PSL.
- Rules that don't touch a divergence point (the majority — SPF/DKIM hygiene,
  unknown-sender detection) are unaffected and carry no regime flag.

### 3.4 Presentation (§7) — avoid "everything twice"
- The failure mode of a parallel view is cognitive overload: two columns on
  every row when 90% are identical. Show one answer where the standards
  agree; show two, clearly labelled, only at divergence points.
- A per-domain **"DMARCbis readiness" panel** is the right primary surface —
  it collects the divergences that apply to *that* domain in one place,
  instead of scattering "bis" badges across every view.
- A small global indicator ("DMARCbis: N domains need attention") on the
  overview dashboard (§7.1) is enough at the top level.

---

## 4. Help-text extensions

The tool's built-in DMARC 101 / contextual help is a differentiator, so the
DMARCbis material belongs there too — not as a separate silo but woven into
the existing articles, since users read help in the context of a finding.

### 4.1 New / revised help articles
- **"DMARC is now a Standard (DMARCbis)"** — a new top-level explainer: what
  RFC 9989/9990/9991 are, that they replace RFC 7489, that `v=DMARC1` records
  keep working, and what (if anything) a reader must act on. Sets expectations
  so the "bis" callouts elsewhere have a home to link to.
- **Org-domain / Tree Walk** — revise any existing article that describes PSL
  based org-domain discovery (D1). This is the most conceptually significant
  change and the one most likely to confuse a knowledgeable user who learned
  the PSL model.
- **Deprecated tags** — a short article covering `pct=`, `rf=`, `ri=` (D2/D3):
  what they did, why they're deprecated, and that removing them is a
  next-DNS-edit task, not urgent.
- **`p=reject` guidance** — revise the enforcement-progression help to reflect
  the flipped/nuanced DMARCbis guidance (D4), since the tool's recommendations
  now reference it.
- **New report fields** — brief coverage of `envelope_from` etc. (D5) where the
  help explains how to read an aggregate report.

### 4.2 Contextual-help wiring
- Each divergence callout in the dashboard (a "differs under DMARCbis" flag on
  a health-check row or recommendation) links to the relevant help article
  above — same contextual-help pattern the tool already uses for findings.
- The **"DMARCbis readiness" panel** links each item to its explainer, so the
  panel doubles as a guided migration walkthrough.
- Keep the writing regime-aware: where an article describes behaviour that
  changed, show both ("Classic DMARC used the PSL; DMARCbis uses a tree
  walk") rather than silently replacing the old explanation — a reader may be
  looking at a classic-era record and needs to recognise it.

### 4.3 Tone / maintenance note
- Frame DMARCbis as evolution, not alarm — mirror the "most records keep
  working" reality so users aren't panicked into unnecessary DNS churn.
- These help texts have a **sunset dimension**: as the deployed base moves to
  DMARCbis, the "classic vs bis" framing becomes less necessary. Write the
  divergence callouts so they can later collapse to single-regime text
  without rewriting whole articles.

---

## 5. Rollout & sunset

1. **Parser field capture (D5)** first — additive, low-risk, immediately
   useful, no UI change.
2. **Tree walk (D1)** in the org-domain logic — the highest-value correctness
   change; verify the algorithm against RFC 9989.
3. **Health-check "DMARCbis readiness" grouping** — the flagship
   user-visible feature; where the parallel framing lives.
4. **Recommendation-engine flags (D2/D4)** — revise R7/R8 and target-policy
   guidance against the RFC.
5. **Help-text pass** — alongside 3 and 4, so callouts have articles to link.
6. **Sunset** — once the deployed base is predominantly DMARCbis, collapse the
   diff view to single-regime and retire the classic-only callouts. Design the
   callouts (and help text, §4.3) so this is a deletion, not a rewrite.

**Verify-before-build (carried from §2):** the tree-walk algorithm, the exact
new-tag set, and the revised `p=reject` wording come from RFC 9989/9990
directly — this document is the integration map, not a substitute for the
RFC text.
