# DMARC Report Analyzer — Technical Spec

**Status:** Draft v1
**Scope:** Personal/internal tool for a handful of domains
**Stack:** PHP 8.3 (strict types), MariaDB 10.11+, Apache, PDO/prepared statements, no heavy framework

---

## 1. Overview

A self-hosted tool that ingests DMARC aggregate reports (and, as an extension, SMTP TLS-RPT reports) sent to a dedicated mailbox, parses them, stores normalized results, enriches source IPs, and presents pass/fail trends and unrecognized senders per domain. Runs alongside the existing LAMP + mail server (Postfix/Dovecot/OpenDKIM) VPS.

### 1.1 Goals
- Ingest and parse `rua` (aggregate) DMARC reports reliably, tolerating vendor XML deviations.
- Normalize records into a queryable schema, deduplicated by report ID.
- Identify and label source IPs (known infra vs. unrecognized senders).
- Provide a per-domain dashboard: volume trends, disposition breakdown, unrecognized-sender alerts.
- Support a handful of domains from day one (schema-level, not necessarily UI polish).
- Lay groundwork for TLS-RPT ingestion via the same pipeline.

### 1.2 Non-goals (v1)
- Multi-tenant / multi-user auth, billing, or customer isolation.
- Forensic (`ruf`) report handling — deprioritized; most major receivers no longer send these.
- Real-time processing — batch/cron-driven ingestion is sufficient.

---

## 2. Architecture

```
[Receiving mail servers]
        │  sends rua reports (gzip/zip + XML attachment)
        ▼
[dmarc-reports@yourdomain.com mailbox] (existing Dovecot)
        │  IMAP poll, cron every 15–30 min
        ▼
[Ingestion script] ── decompress ── [Parser] ── [DB writer]
        │                                            │
        ▼                                            ▼
   [raw XML archive]                          [MariaDB: reports,
   (compressed, retained)                      report_records,
                                                auth_results]
                                                      │
                              ┌───────────────────────┼───────────────────────┐
                              ▼                                               ▼
                     [Enrichment job]                                [Dashboard (Apache/PHP)]
                     (rDNS, ASN/org lookup,                            per-domain views,
                      allowlist matching)                              trend charts, tables
                                                                              │
                                                                              ▼
                                                                     [Alert cron → email
                                                                      via existing Postfix]
```

All components are cron-driven PHP CLI scripts plus a thin web front-end. No queue/message broker needed at this scale.

---

## 3. Data model

### 3.1 `domains`
| Column | Type | Notes |
|---|---|---|
| id | INT PK | |
| domain | VARCHAR(255) UNIQUE | e.g. `example.com` |
| current_published_policy | VARCHAR(64) | auto-read from DNS (`p`/`sp`/`pct`/`adkim`/`aspf`); refreshed on health check / ingestion |
| approved_baseline_policy | VARCHAR(64) | admin-approved known-good state; R9 drift baseline (§10.6) |
| baseline_approved_at | DATETIME | when the baseline was last affirmatively approved |
| target_policy | VARCHAR(64) | desired end state R7/R8 advance toward; default `p=reject; sp=reject` |
| non_sending | TINYINT(1) | flags a domain that should never send mail (enables R10) |
| active | TINYINT(1) | |

### 3.2 `reports`
| Column | Type | Notes |
|---|---|---|
| id | INT PK | |
| domain_id | INT FK → domains | |
| reporter_org | VARCHAR(255) | e.g. `google.com` |
| report_id | VARCHAR(255) | from XML `<report_id>` |
| date_begin | DATETIME | |
| date_end | DATETIME | |
| raw_file_hash | CHAR(64) | SHA-256 of decompressed XML; dedup key |
| received_at | DATETIME | |
| UNIQUE | (domain_id, reporter_org, report_id) | prevents duplicate ingestion |

### 3.3 `report_records`
| Column | Type | Notes |
|---|---|---|
| id | BIGINT PK | |
| report_id | INT FK → reports | |
| source_ip | VARBINARY(16) | store as binary (INET6_ATON) for both v4/v6 |
| count | INT | |
| disposition | ENUM('none','quarantine','reject') | policy evaluated |
| dkim_result | ENUM('pass','fail') | evaluated |
| spf_result | ENUM('pass','fail') | evaluated |
| header_from | VARCHAR(255) | |

### 3.4 `auth_results`
| Column | Type | Notes |
|---|---|---|
| id | BIGINT PK | |
| record_id | BIGINT FK → report_records | |
| type | ENUM('dkim','spf') | |
| domain | VARCHAR(255) | auth domain used |
| selector | VARCHAR(255) | NULL for spf |
| result | VARCHAR(32) | raw result string (pass/fail/neutral/etc.) |

### 3.5 `ip_enrichment`
| Column | Type | Notes |
|---|---|---|
| source_ip | VARBINARY(16) PK | |
| rdns | VARCHAR(255) | |
| asn | INT | |
| asn_org | VARCHAR(255) | |
| label | VARCHAR(64) | 'known' / 'unknown' / manual override |
| last_seen | DATETIME | |
| lookup_at | DATETIME | cache timestamp — re-lookup periodically |

### 3.6 `known_senders` (manual allowlist)
| Column | Type | Notes |
|---|---|---|
| id | INT PK | |
| domain_id | INT FK → domains | |
| ip_or_cidr | VARCHAR(64) | supports single IP or CIDR |
| label | VARCHAR(128) | e.g. "SMTP relay", "ESP" |

### 3.7 `tls_rpt_reports` / `tls_rpt_records` (extension, phase 2)
Mirrors the `reports`/`report_records` split for RFC 8460 JSON reports — separate tables since the schema (policy types, failure reason codes) doesn't map cleanly onto DMARC's.

---

## 4. Ingestion pipeline

1. **Cron trigger** (every 15–30 min): `bin/ingest.php`
2. Connect to `dmarc-reports@yourdomain.com` via IMAP using **`webklex/php-imap`** (a maintained pure-PHP IMAP client). Do **not** use the native `ext/imap` — it was unbundled to PECL in PHP 8.4, is no longer maintained, and its underlying c-client library has been unmaintained for ~20 years. `webklex/php-imap` also avoids the c-client build dependency and adds OAuth support (useful if ingestion ever points at a Microsoft/Google mailbox instead of local Dovecot).
3. For each unseen message:
   a. Extract attachment(s).
   b. Sniff magic bytes to determine gzip vs zip (don't trust filename/Content-Type).
   c. Decompress to XML.
   d. Compute SHA-256 of the XML for dedup.
   e. Parse (§5).
   f. On success: write to DB, archive raw XML (compressed) to disk, mark message read/move to processed folder.
   g. On parse failure: move to a `failed/` IMAP folder or local dir for manual inspection, log the error — do not silently drop.
4. Idempotency: re-running ingestion on an already-processed message must not create duplicate rows (enforced by the `UNIQUE` constraint on `reports`).

### 4.1 Ingestion security hardening (hostile input)

The `rua` address is published in DNS, so **anyone on the internet can send crafted "reports" to it**. All ingested content is untrusted and must be treated as potentially hostile, not merely malformed. This is the highest-priority security control in the tool.

- **XXE (XML external entities)**: on the target stack (PHP 8.3+, libxml ≥ 2.9) external-entity substitution is **off by default** and `libxml_disable_entity_loader()` is deprecated — so the rule is simply: **never pass `LIBXML_NOENT` or `LIBXML_DTDLOAD`** to the parse call (those re-enable the risk). On PHP 8.4 / libxml ≥ 2.13, additionally pass the explicit `LIBXML_NO_XXE` flag as defense-in-depth. Do not rely on the deprecated loader function. This prevents an attacker's XML from reading local files or triggering SSRF.
- **Entity-expansion / "billion laughs" DoS**: reject documents with excessive entity expansion; do not enable `LIBXML_NOENT`.
- **Decompression bombs**: a few-KB gzip/zip can inflate to gigabytes. Enforce a maximum decompressed-size ceiling and abort inflation once exceeded — decompress through a bounded stream, never inflate-then-check. Also cap zip entry count / nesting.
- **Attachment & message size caps**: bound accepted attachment size before decompression; reject oversized messages.
- **Per-sender rate/volume caps**: limit how much a single sender address/IP can submit per window so the mailbox can't be flooded into a disk-fill or parser-DoS.
- **Fail safe, not open**: any input tripping these limits goes to the `failed/` quarantine (per step 3g) and is logged — never partially ingested.
- **Filesystem safety**: never derive archive file paths from attacker-controlled attachment filenames (path traversal); generate internal names from the content hash.

---

## 5. Parsing

- Use `DOMDocument` with `libxml_use_internal_errors(true)` to tolerate malformed XML without hard-crashing the batch.
- Map RFC 7489 elements to the schema in §3. Key elements: `report_metadata` (org, report_id, date_range), `policy_published`, and one `<record>` per source IP with `row/source_ip`, `row/count`, `row/policy_evaluated`, `auth_results/dkim[]`, `auth_results/spf[]`.
- Log and skip individual malformed `<record>` blocks rather than rejecting the whole report where possible.
- Domain matching: `report_metadata` doesn't always cleanly state which of your domains the report is for — match on `policy_published/domain`.

---

## 6. Enrichment

- **Reverse DNS**: `gethostbyaddr()` or async batch resolution.
- **ASN/org lookup**: local MaxMind GeoLite2-ASN DB (or equivalent) to avoid rate-limited external API calls; refresh DB monthly.
- **Labeling logic**: on ingestion of a new/updated `source_ip`, check `known_senders` (CIDR match) first; fall back to ASN-based heuristic labels; otherwise mark `unknown`.
- Enrichment runs as a separate cron step (or inline post-insert) — decoupled from parsing so a slow DNS/ASN lookup never blocks report ingestion.
- **Note**: source IPs are personal data and enrichment is profiling — see §14 (Data protection) for lawful basis, retention, and third-party-transfer considerations.

---

## 7. Presentation (dashboard)

Plain PHP pages, no JS framework required at this scale.

### 7.1 Overview dashboard (landing page)
A single at-a-glance view across **all** domains the user can see (scoped by role, §15):
- **Per-domain posture cards**: current effective policy (`none`/`quarantine`/`reject`), latest health-check grade (§11), pass-rate trend sparkline, and count of open recommendations by severity.
- **Attention panel**: highest-severity open recommendations and recent High alerts across all domains, so the first screen answers "what needs me today."
- **Ingestion health indicator**: last successful report ingestion time and last health-check run — surfaces a stalled pipeline immediately (ties to the heartbeat alert, §8).
- **Recent activity**: newly seen unknown senders, policy changes detected, domains onboarded.

### 7.2 Per-domain views (drill-down)
- **Domain overview**: pass/fail volume over time (Chart.js fed by a JSON endpoint), current effective policy, health-check results.
- **Source table**: IP, rDNS, ASN org, label (known/unknown), volume, DKIM/SPF/DMARC alignment — sortable, filterable by label.
- **Recommendations panel**: per §10.5.
- **Report detail**: raw per-record view for drilling into a specific report.

### 7.3 Access
Authentication and authorization are covered in §15 (User management & RBAC). The dashboard enforces role scope on every view and every JSON endpoint server-side — never rely on the UI hiding a control as the access boundary.

---

## 8. Alerting

- Daily cron (`bin/alert.php`): flags and emails (via existing Postfix) when:
  - A new `unknown`-labeled IP exceeds a configurable volume threshold.
  - Overall DMARC pass rate for a domain drops below a threshold vs. its trailing average.
  - The domain's live DMARC record (`current_published_policy`) no longer matches its `approved_baseline_policy` (detects unexpected DNS record changes — R9).
  - **Heartbeat / dead-man's-switch**: *no* reports ingested for a domain in N days (configurable). This catches both a broken ingestion pipeline (IMAP poll down, mailbox full) and a tampered/removed `rua` DNS record — failure modes that are otherwise silent because the symptom is *absence* of data. Pair with an ingestion-health indicator on the overview dashboard (§7.1).

---

## 9. Derived technical measures

What findings from the reports translate into, grouped by category. This is the "so what" layer — the actions the tool exists to inform.

### 9.1 From legitimate-but-failing senders (auth hygiene)
- **Update SPF**: add `include:` for the sending service or the relay IP/CIDR — resolves the most common failure cause.
- **Fix SPF lookup-limit `permerror`**: if near/over the 10-DNS-lookup limit, flatten or drop unused includes. Reports show which senders are worth keeping.
- **Enable/repair DKIM signing** per legitimate sending path: get the service to sign, publish the selector, verify alignment. A source passing SPF but failing DKIM usually just needs signing turned on.
- **Fix alignment-mode mismatches**: a subdomain signature under `adkim=s` (strict) fails; either relax to `adkim=r` or align the signing domain. Reports reveal which.

### 9.2 From spoofing / unrecognized sources (policy tightening)
- **Ratchet policy toward enforcement**: `p=none → quarantine → reject`, using the reports as evidence that no legitimate source will break.
- **Stage with `pct=`** (e.g. `p=quarantine; pct=25`) and watch reports for fallout before going to 100%.
- **Set `sp=reject` explicitly**: attackers frequently spoof non-existent subdomains that inherit a weaker default.
- **Lock down non-sending domains/subdomains**: publish `v=spf1 -all` + `p=reject` + null DKIM for anything that legitimately never sends.

### 9.3 Infrastructure hardening
- **Retire/authenticate forgotten senders** surfaced by reports (old dev box, marketing tool, misconfigured relay).
- **Tighten the local outbound path**: confirm OpenDKIM signs correctly for every hostname/subdomain Postfix emits — reports show any unsigned path.

### 9.4 Inbound-blocking crossover (narrow — apply with care)
- Source IPs/domains that consistently spoof the domain are *candidate* feed entries for the RHSBL/access-map or nftables inbound blocklist.
- **Caveat**: a source spoofing the domain *to third parties* is not necessarily sending *to* this server, so inbound-blocking it may accomplish nothing. Only wire in sources also observed hitting the local MX. Do **not** naively pipe `rua` source IPs into inbound blocks.
- More reliable use: abuse patterns (e.g. a hosting ASN heavily forging the domain) inform which providers to file abuse reports against.

### 9.5 Detection / tamper measures (operational)
- **Policy-drift alert**: `current_published_policy` ≠ `approved_baseline_policy` flags an unauthorized/accidental DNS change (tamper/misconfig detector). Mirrors §8/R9.
- **New-unknown-sender alert** above a volume threshold: early warning of a spoofing campaign.
- **Pass-rate regression alert**: a sudden drop flags either a broken legitimate sender (a shipped config change) or an abuse spike.

### 9.6 Governance
- Reports provide the evidence base for a **sender-authorization process**: every new service that sends as the domain must be added to SPF/DKIM deliberately, and reports catch anything that skips it.

**Framing**: the primary technical output is authentication hygiene + a safe path to `p=reject`; the primary security output is spoofing visibility + DNS tamper detection. The inbound-blocking crossover is real but narrow.

---

## 10. Recommendation engine (findings → recommendations)

§9 is the human catalog of what findings mean; this section specifies how the **tool** derives concrete, prioritized recommendations automatically. It's a deterministic rule engine over the enriched data — not ML, not guesswork. Every recommendation must be traceable to the specific records that triggered it.

### 10.1 Design principles
- **Deterministic and explainable**: each recommendation cites the exact evidence (source IPs, counts, date range, auth results) that produced it. No opaque scoring the user can't audit.
- **Classification-driven**: a recommendation's *type* and *urgency* depend first on whether the triggering source is `known` (allowlisted/enriched-as-infra) or `unknown`. The same failure means very different things in each case.
- **Idempotent per evaluation window**: re-running analysis over the same data yields the same recommendations; state (acknowledged / suppressed / resolved) is tracked separately so recommendations don't nag once actioned.
- **Conservative on inbound-blocking**: per §9.4, never recommend inbound blocks from `rua` data alone — only surface as "investigate," never "block," unless the source is also observed on the local MX.

### 10.2 Inputs
Per domain, over a configurable window (default: trailing 7 and 30 days):
- Aggregated `report_records` grouped by `source_ip` + auth outcome.
- `ip_enrichment` labels (known/unknown, ASN/org).
- `known_senders` allowlist matches.
- Current published policy (`current_published_policy`) vs. the `approved_baseline_policy` and `target_policy` values stored per domain (§10.6).
- SPF lookup count for the domain's live record (computed at analysis time).

### 10.3 Rule catalog (v1)
Each rule = trigger condition → recommendation + severity + evidence. Illustrative, not exhaustive; encode as data (table/config) not hardcoded logic so rules are tunable.

| # | Trigger condition | Recommendation | Severity |
|---|---|---|---|
| R1 | `known` sender, SPF fail, DKIM pass, aligned | Add sender's IP/include to SPF | Low |
| R2 | `known` sender, DKIM fail, SPF pass | Enable/repair DKIM signing for this path | Low |
| R3 | `known` sender, auth passes but alignment fails | Relax alignment (`adkim`/`aspf=r`) or align signing domain | Low |
| R4 | SPF record resolves > 10 DNS lookups | Flatten/prune SPF includes (`permerror` risk) | Medium |
| R5 | `unknown` source, failing auth, volume > threshold | Investigate possible spoofing; do NOT auto-block inbound | High |
| R6 | `unknown` source, failing auth, sustained across window | Likely spoofing campaign; consider abuse report to hosting ASN | High |
| R7 | All legitimate sources passing for full window at `p=none`, and `target_policy` is stricter | Safe to advance policy → `quarantine` (staged `pct=`) toward `target_policy` | Medium |
| R8 | Domain at `quarantine`, no legitimate fallout at current `pct`, `target_policy` stricter still | Advance `pct` or move to `reject` toward `target_policy` | Medium |
| R9 | `current_published_policy` ≠ `approved_baseline_policy` | DNS drift/tamper — reconcile record (or approve as new baseline if the change was intentional) | High |
| R10 | Domain flagged non-sending but records observed | Lock down (`-all`, `p=reject`) or authorize the unexpected sender | Medium |
| R11 | `sp` unset while subdomain spoofing observed | Publish explicit `sp=reject` | Medium |
| R12 | Forwarding-pattern failures (known forwarders) | Informational only — do not weaken policy to "fix" | Info |

### 10.4 Severity & prioritization
- **High**: active spoofing signal or DNS tamper/drift (R5, R6, R9) — surfaced first, eligible for alerting (§8).
- **Medium**: policy-advancement opportunities and structural risks (R4, R7, R8, R10, R11).
- **Low**: routine auth-hygiene fixes for known senders (R1–R3).
- **Info**: expected-behavior notes that prevent misguided action (R12).
- Prioritization key: `(severity, volume, recency)` — highest severity, then largest count, then most recent.

### 10.5 Output
- **Storage**: a `recommendations` table — `id`, `domain_id`, `rule_id`, `severity`, `evidence_json` (the triggering records/IPs/counts), `first_seen`, `last_seen`, `state` (`open`/`acknowledged`/`suppressed`/`resolved`), `resolved_at`.
- **Auto-resolution**: a recommendation whose trigger no longer fires in a later window transitions to `resolved` automatically (e.g. SPF was fixed → R1 clears).
- **Dashboard**: a per-domain "Recommendations" panel, sorted by priority, each row expandable to its evidence and a suggested concrete change (e.g. the exact SPF token to add, cross-referencing the per-domain checklist).
- **User actions**: acknowledge (seen, will act), suppress (known-and-accepted, stop showing — e.g. a forwarder), with an audit trail of who/when for governance.

### 10.6 Config additions
- Per-domain **policy fields** (three distinct values — a single "intended" field can't serve both drift detection and enforcement-advancement, since they need different reference points):
  - `current_published_policy` (`p`/`sp`/`pct`/`adkim`/`aspf`) — **auto-read** from DNS at onboarding and refreshed on every health check / report ingestion. Pure observation; never hand-entered.
  - `approved_baseline_policy` — the known-good state **R9** compares against for drift/tamper. Seeded from `current_published_policy` at onboarding but requires an explicit admin "approve this baseline" confirmation, and is updated deliberately whenever DNS is intentionally changed. Seeding is not silent copying — otherwise an already-tampered or suboptimal record gets baptized as "good."
  - `target_policy` — the desired end state **R7/R8** advance toward. Cannot be read from DNS (it's where you want to be, not where you are). Defaults to `p=reject; sp=reject`, adjustable per domain.
- Per-rule **thresholds** (volume for R5, window length for R6/R7) — tunable without code changes.
- Per-domain **non-sending flag** — enables R10.

### 10.7 Explicit limits
- Recommendations are **advisory**: the tool never edits DNS or mail config itself — it produces the change for a human to apply. (Auto-remediation is deliberately out of scope for v1 given the blast radius of a wrong DNS change.)
- The engine reasons only over what `rua` data contains (§ "What they do not give you" in the analysis) — it cannot recommend on message content, inbound threats, or real-time events.
- Rule outputs are only as good as enrichment/allowlist accuracy; a mislabeled `known`/`unknown` source produces a wrong-severity recommendation. Allowlist hygiene is a prerequisite, not an afterthought.

### 10.8 Optional: community threat reporting (manual, opt-in)

A **manual** action to contribute a confirmed spoofing indicator to the Spamhaus Threat Intel Community (the portal accepts suspicious IPs, domains, URLs, and raw email source). Deliberately **not** an automated feed — see the constraints below.

- **Trigger surface**: a "Report to Spamhaus Threat Intel Community" button on individual findings, available **only** on high-confidence spoofing findings — i.e. `unknown` source, failing auth, sustained across the window, above volume threshold (R6-class). Not offered on R1–R4 hygiene findings, forwarders, or anything involving a `known`/allowlisted source.
- **Human-in-the-loop is mandatory**: the button opens a review step where an operator confirms the indicator is genuinely malicious (not a misconfigured ESP/forwarder) before anything is submitted. Nothing leaves the system without an explicit human action per indicator. No bulk auto-submit.
- **Why manual (design rationale)**:
  - `rua` data is *weak evidence* for a blocklist submission — a DMARC failure is not proof of malice, and the same spoofing-vs-misconfiguration caveat as §9.4 applies. Auto-submitting raw failures would list legitimate senders.
  - Spamhaus reviews submissions against list policy and scores **contributor reputation on accuracy** — a curated trickle of verified indicators is worth more (to us and them) than a noisy firehose, which would degrade our contributor standing.
  - Aggregate reports lack the richest submission material (raw phishing source / URLs) by design — that lives in `ruf`/message content, which the tool deliberately does not ingest (§14). So only the IP/domain indicator is ever shareable.
- **Data-protection gate (§14)**: submitting a source IP (personal data) to a third party for listing is a processing/transfer decision. Before this feature is enabled, the operator must complete a T&C + GDPR review (Spamhaus's submission terms + our own lawful-basis/transfer assessment). The feature ships **disabled by default** with a config flag that gates it until that review is recorded.
- **Submission path**: via the Threat Intel Community portal / its API (requires a contributor account). Store no Spamhaus credential in cleartext; treat any API key like the DQS/GeoLite2 keys (app config).
- **Audit**: every submission is written to the `audit_log` (§15.7) — who submitted, which indicator, evidence snapshot, and outcome.
- **Scope note**: malware payloads / botnet C2 are handled by Spamhaus's partner abuse.ch, not this portal — out of scope for a DMARC tool; noted only so the channel isn't confused.

---

## 11. Domain health check (onboarding + on-demand)

A point-in-time assessment run when a domain is onboarded (and re-runnable on demand / scheduled). Unlike the report analysis — which is retrospective and depends on `rua` data arriving — the health check probes the domain's *currently published* posture directly via DNS and network checks. It gives an immediate baseline before a single report exists, and re-runs let you confirm that a change actually took effect.

### 11.1 Scope & relationship to the rest of the tool
- **Independent of report data**: works on a freshly added domain with zero reports.
- **Feeds the recommendation engine (§10)**: health-check findings are additional triggers — e.g. "no DMARC record published" or "SPF `permerror`" produce recommendations the same way report-derived findings do.
- **Not real-time monitoring**: it's a snapshot. Scheduling it (e.g. weekly) turns it into drift detection that complements the report-based `current_published_policy` check (§8/R9).
- **Populates the domain's policy fields on onboarding**: the health check auto-reads the live DMARC record into `current_published_policy`, then presents it to the admin for an explicit **"approve as baseline"** action that sets `approved_baseline_policy` (§10.6). `target_policy` defaults to `p=reject; sp=reject`. The approval is deliberate, not silent — so R9's notion of "known-good" is something a human signed off on, not whatever happened to be in DNS that day.

### 11.2 Checks

**DNS / authentication posture**
- **SPF**: record present? exactly one `v=spf1` record (multiple = misconfig)? syntactically valid? resolved DNS-lookup count ≤ 10 (else `permerror`)? qualifier on `all` (`-all` / `~all` / `?all` / `+all` — flag `+all` as dangerous, `?all`/`~all` as weak)?
- **DMARC**: `_dmarc` record present? valid syntax? policy level (`none` / `quarantine` / `reject`)? `rua` present — and does it include the tool's ingestion mailbox? `sp` set? `pct` value? alignment modes.
- **External report-destination authorization**: if the domain's `rua` sends reports to a mailbox on a *different* domain (e.g. all domains report to a mailbox on silverday.de), RFC 7489 §7.1 requires the destination domain to publish an authorization record. Format: at `<policy-domain>._report._dmarc.<destination-domain>`, a TXT record with value `v=DMARC1`. Example — for roya.at reporting to a silverday.de mailbox, silverday.de must publish `roya.at._report._dmarc.silverday.de IN TXT "v=DMARC1"`. Without it, some receivers refuse to send reports at all — producing silent data gaps. The health check verifies this record exists for every domain whose `rua` is cross-domain, and the onboarding flow / checklist should generate the exact record per domain.
- **DKIM**: *see limitation in 11.4* — probe a configurable list of common/known selectors and any selectors already observed in this domain's reports; report which resolve to a valid key. Cannot be exhaustive.
- **MX**: records present, resolve to A/AAAA, and are reachable on 25? Note MX host IPs for the blocklist checks below.
- **DNSSEC**: is the zone signed (AD bit / DS present)? Informational — absence isn't a mail failure but is a posture signal.
- **MTA-STS**: `_mta-sts` TXT present and the policy file served over HTTPS at the well-known URL? **TLS-RPT**: `_smtp._tls` record present (ties into the phase-2 TLS-RPT ingestion)?
- **BIMI** (optional/informational): `_bimi` record present?

**Transport security**
- MX offers STARTTLS? Certificate valid (not expired, hostname matches, chain trusted)?

**Reputation / blocklists**
- **IP-based DNSBLs**: check the domain's MX / known sending IPs against a configurable set (e.g. Spamhaus ZEN, others).
- **Domain-based RHSBL/DBL**: check the domain itself against domain blocklists (e.g. Spamhaus DBL).
- **rDNS/PTR**: sending IPs have a PTR that resolves forward-confirmed (FCrDNS) and is consistent with HELO — a common deliverability/reputation factor.

### 11.3 Output & scoring
- **Storage**: a `health_checks` table (`id`, `domain_id`, `run_at`, `trigger` = onboarding/manual/scheduled) plus `health_check_items` (`check_id`, `category`, `check_name`, `status` = pass/warn/fail/info/error, `detail_json`, `evidence`). Keep history so re-runs are comparable over time.
- **Per-check status**, not just a single number — a domain can be `reject`-enforced (good) but on a DBL (bad); collapsing to one score hides that. If a headline grade is wanted, derive it from weighted category results and always keep it expandable to the underlying checks.
- **`error` is a distinct status from `fail`**: a blocklist query that timed out or a DNS resolution error must not be reported as "clean" or "listed" — it's *unknown*, and shown as such. (Consistent with the never-assume principle: an un-run check is not a passing check.)
- Findings flow into the §10 recommendation engine and the per-domain dashboard.

### 11.4 Limitations & accuracy notes (verify before build)
- **DKIM is not enumerable**: selectors cannot be discovered from DNS alone by design. The health check can only probe *known/guessed* selectors and selectors seen in reports — it can confirm a selector works but can never certify "DKIM is fully correct" at onboarding. Authoritative DKIM coverage comes from the ongoing report analysis. State this clearly in the UI so a "no DKIM found" result isn't misread as definitive.
- **Blocklist query terms**: public DNSBL/RHSBL providers impose usage conditions that must be confirmed against current provider policy before building — several (Spamhaus in particular) block queries from large public/shared resolvers and require queries from your own recursive resolver, with volume limits and a keyed data service for higher-volume or commercial use. Do **not** hardcode assumptions about query mechanics or limits; treat provider terms as a build-time verification item.
- **Reachability probes**: connecting to MX on 25 / testing STARTTLS is active network behavior — keep it lightweight and rate-limited, and never perform intrusive tests (e.g. open-relay probing) without explicit intent; out of scope for v1.
- A health check reflects DNS/network state *at run time* and is subject to propagation and caching — re-run and verify rather than trusting a single result.

### 11.5 Config additions
- Per-tool **DNSBL/RHSBL provider list** with the resolver to query through (see 11.4 and 11.6).
- **Common-DKIM-selector list** to probe (tunable).
- **Schedule** for periodic re-runs (optional; default onboarding + manual only).

### 11.6 Spamhaus DQS requirement (resolved)

The Spamhaus free **Public Mirrors** prohibit queries from resolvers without attributable reverse DNS, and this explicitly includes major hosting/cloud provider networks; such queries are progressively being cut off and return the error code `127.255.255.254` instead of real answers. A naïve "query Spamhaus over the box's default resolver" approach will therefore silently stop working (or worse, be misread) if the VPS sits on an affected network.

Resolution for this tool:
- Use the **free Data Query Service (DQS)** — register for a free, non-commercial key that tracks query volume; queries then go to keyed DQS zones. This tool's volume (a handful of lookups per health-check run across 10 domains) is comfortably within free/non-commercial fair use.
- **Register at:** https://www.spamhaus.com/free-trial/free-trial-for-data-query-service/ — complete the form, verify your email, then retrieve the DQS key from the portal (under the "Datafeed Query Service" section). No credit card required.
- **Register from a clean state**: don't wire up any Public-Mirror Spamhaus queries before registering — if the requesting infrastructure is already tripping fair-use errors, Spamhaus's verification email may not arrive. A fresh install has no such config, so this is a non-issue as long as DQS is set up before any blocklist query path goes live.
- **Confirm the free tier fits**: the free DQS is for non-commercial, low-volume use, subject to Spamhaus's terms. This tool's volume qualifies, but the *purpose* is the thing to check — if the reputation data ends up serving a commercial/organizational use, Spamhaus's terms point to a paid tier. Read their terms against your own context before relying on the free key. (Also: the site surfaces a separate "30-day trial" of the paid IP+Content product — that is *not* the free DQS; the permanent free DQS is the right option here.)
- Store the **DQS key in app config** (same pattern as the GeoLite2 key).
- Alternatively, query through a **local recursive resolver on the VPS with attributable reverse DNS** — but DQS is the simpler, provider-blessed path and avoids the reverse-DNS-attribution problem entirely, so it's the default recommendation.
- This is exactly the "confirm provider terms before wiring in blocklists" caveat from §11.4, now resolved: **DQS key, not raw Public Mirror queries.**
- Reminder from §11.3: a `127.255.255.254` (or any error) response is an **`error`/unknown** status, never "clean" — the tool must distinguish a real not-listed answer from a blocked/misconfigured query.

---

## 12. TLS-RPT extension (phase 2)

- Same mailbox/ingestion pattern; RFC 8460 reports are JSON (optionally gzipped), not XML — parser is a separate code path but shares the ingestion/dedup/archive scaffolding.
- Low priority relative to DMARC since volume and actionability are lower, but cheap to add once the pipeline exists.

---

## 13. Retention & ops

- Retain compressed raw XML/JSON indefinitely (cheap) to allow re-parsing after parser bug fixes.
- `report_records`/`auth_results` retention: no hard requirement at this scale; consider a multi-year window before any pruning.
- Backups: covered by existing VPS backup strategy — confirm this tool's DB is included.

---

## 14. Data protection (GDPR / EU-DE context)

**Characterization of the data (corrected):** in a DMARC aggregate report the `source_ip` is the transmitting **MTA**, not an end-user device. For the overwhelming majority of records this is a sending mail server operated by a **legal person / organization** (ESP, provider, corporate relay). GDPR protects *natural* persons and does not cover legal persons (Recital 14), so these mail-server IPs are generally **not personal data**, and the rDNS/ASN enrichment resolves the *operating organization* — legal-person identification, not natural-person profiling.

A **residual subset** can still relate to a natural person and must not be assumed away: an individual self-hoster's MTA on a residential line or personal VPS; compromised/residential hosts appearing as `unknown` spoofing sources. Per the CJEU *Breyer* line (C-582/14), an IP *can* be personal data for a party with lawful means to identify the person behind it. So the accurate position is neither "all IPs are personal data" nor "no IP is" — the vast majority fall outside GDPR scope, with a context-specific residual. **The DPO makes this determination for these domains; the spec does not assert it.**

The controls below are framed as good-practice-regardless, applying with full force to any records the DPO's assessment does treat as personal data:

- **Lawful basis** (for any in-scope IP data): legitimate interest in email-domain security is the typical fit; record the assessment.
- **Data minimization**: store only what analysis needs. Independently reinforces the decision to deprioritize `ruf`/forensic reports, which carry genuine PII (message fragments, recipient data) that aggregate reports do not — the `ruf` case is a real personal-data concern regardless of the source-IP characterization above.
- **Retention limits**: still replace §13's "retain indefinitely" with a defined, justified retention for `report_records`/`ip_enrichment` — sound operational hygiene even where the data isn't personal, and required where the residual assessment says it is.
- **Third-party transfers**: enrichment/blocklist lookups disclose IPs to external parties. The *local* MaxMind DB (design default in §6) avoids per-query transfer; DNSBL/DQS lookups inherently disclose the queried IP to the provider; the optional §10.8 Spamhaus submission is a deliberate onward disclosure gated on the DPO review. Assess these as transfers to the extent any queried IP is in-scope.
- **Access & audit**: IP data access is gated by RBAC (§15) and user actions are audit-logged — appropriate irrespective of classification.
- **Data-subject considerations**: for any in-scope residual, document how a request would be handled. This section is a placeholder for the DPO's own formal assessment, not legal advice from the spec.

---

## 15. User management & RBAC

Invitation-based user management with three roles. Roles are **global** — they apply across all domains. This is a deliberate single-tenant design: there is no per-domain role scoping, since the tool serves one organization's own domains.

### 15.1 Roles

| Role | User management | Domain management | Data access |
|---|---|---|---|
| **Super admin** | Yes — invite/disable users, assign roles | Yes — onboard/configure/remove domains | Full read + act on recommendations |
| **Admin** | No | Yes — onboard/configure domains, run health checks, act on recommendations, edit allowlists | Full read + act |
| **Read-only** | No | No | Read dashboards, reports, recommendations, health checks — no state changes |

- The hierarchy is clean and non-overlapping: Read-only ⊂ Admin ⊂ Super admin, with Super admin's *only* additional power over Admin being user management. That distinction is the reason to separate the two tiers; if you never need more than one user who manages others, Admin and Super admin could collapse — but keeping them split is cheap and future-proofs delegation.
- At least one Super admin must always exist (block disabling/demoting the last one).

### 15.2 Invitation flow
- A Super admin invites by email; the system generates a **single-use, expiring, high-entropy invitation token** (store only a hash of it, not the raw token).
- The invitee sets their own credential via the tokened link; the token is consumed on use and invalidated on expiry.
- No open/self-service registration — invitation is the only account-creation path (appropriate for an internal security tool).

### 15.3 Authentication (per NIST SP 800-63B baseline)

Supports two authenticator types; MFA is **required**, not optional, for all roles given the tool holds personal data and security findings (63B AAL2 posture).

**Passkeys (WebAuthn/FIDO2) — preferred**
- Passwordless, phishing-resistant credentials bound to the origin; a passkey satisfies MFA on its own (possession + local user verification), so a passkey user needs no separate second factor.
- Support multiple passkeys per user (e.g. laptop + phone + a hardware key as backup) so losing one device isn't a lockout.
- Store only public keys and credential metadata — never anything secret server-side.

**Password + second factor — fallback**
- Password storage and policy per 800-63B: verifier-side hashing with an approved algorithm (e.g. Argon2/bcrypt), check against known-breached-password lists, no forced periodic rotation, generous length limits, no composition rules that hurt usability.
- Second factor required for password users: **TOTP** (self-hostable, no external dependency) and/or a WebAuthn security key as the second factor.
- Recovery codes: issue a set of single-use backup codes when a second factor is enrolled (hashed at rest), so a lost TOTP device isn't an automatic admin-reset.

**Session management**: server-side sessions, secure/HttpOnly/SameSite cookies, idle + absolute timeouts, TLS-only. Re-prompt for authentication (step-up) on sensitive actions — role changes, user disable, domain removal.

### 15.4 Credential lifecycle (self-service)

- **Change password**: authenticated user changes their own password — requires re-entering the current password (or a step-up auth for passkey-only users), enforces the 800-63B checks in 15.3, invalidates other active sessions on success, and is audit-logged. Never email the old or new password.
- **Manage MFA / passkeys**: a self-service security page to enrol/remove passkeys, enrol/reset TOTP, and regenerate recovery codes. Removing the last remaining factor is blocked (MFA is mandatory); adding a new factor requires a step-up auth.
- **Forgotten password (self-service reset)**:
  - User requests reset by email; system issues a **single-use, short-expiry, high-entropy token** (store only its hash).
  - **Non-enumerating response**: the UI shows the same "if that address exists, a link has been sent" message whether or not the account exists — no confirmation of which emails are registered.
  - The tokened link lets the user set a new password; **MFA is still required at the subsequent login** — a password reset must not bypass the second factor (an email-account compromise otherwise defeats MFA entirely).
  - Reset consumes the token, invalidates all existing sessions, and is audit-logged. Rate-limit reset requests per account/IP.
  - **Forgotten second factor** (lost TOTP/passkey, no recovery codes) is deliberately *not* self-service — it routes to an admin action (15.5), since self-service recovery of the possession factor would undermine MFA.

### 15.5 Admin-side account actions

Performed by Super admin (user management is Super-admin-only per 15.1), all audit-logged, all requiring the actor's step-up auth:

- **Invite / re-invite**: issue or reissue an invitation (per 15.2); reissuing invalidates the prior token.
- **Disable / re-enable / delete**: disabling immediately invalidates the user's active sessions and blocks login; the last Super admin cannot be disabled/demoted (15.1).
- **Change role**: promote/demote within the three roles.
- **Trigger password reset**: send a user a reset link (same mechanism as self-service) — the admin never sets or sees a user's password.
- **Reset/clear MFA**: for a user locked out of their second factor. This is a sensitive action — it must be step-up-authenticated, audit-logged with reason, and force the user to re-enrol a factor at next login (they cannot proceed MFA-less). Consider requiring that a user re-verify identity out-of-band before an admin clears MFA, to prevent this becoming a social-engineering bypass.
- **Force logout / revoke sessions**: terminate a user's sessions on demand.
- Admins **cannot** read credentials, TOTP secrets, or passkey private material — none exist server-side in usable form.

### 15.6 Authorization enforcement
- Enforce role checks **server-side on every action and JSON endpoint**, not by hiding UI controls. The UI reflects permissions for UX; the server is the boundary.
- Deny-by-default: an endpoint with no explicit role grant is inaccessible.

### 15.7 Audit log
An append-only `audit_log` (`id`, `actor_user_id`, `action`, `target`, `detail_json`, `timestamp`, `source_ip`) recording at minimum: logins (success/fail), password changes/resets, MFA/passkey enrolment and removal, admin MFA resets (with reason), invitations issued/consumed, role changes, user disable/enable/delete, session revocations, domain onboarding/removal, allowlist edits, and recommendation state changes. This is both good practice for a security tool and supports the governance angle noted in §9.6/§10.5.

### 15.8 Data model additions
- `users` (`id`, `email`, `credential_hash` [nullable — passkey-only users have none], `totp_secret` [nullable, encrypted at rest], `role`, `status` = invited/active/disabled, `created_at`, `last_login_at`).
- `webauthn_credentials` (`id`, `user_id`, `credential_id`, `public_key`, `sign_count`, `label`, `created_at`, `last_used_at`) — one row per enrolled passkey/security key.
- `recovery_codes` (`id`, `user_id`, `code_hash`, `consumed_at` [nullable]).
- `invitations` (`id`, `email`, `token_hash`, `role`, `invited_by`, `expires_at`, `consumed_at` [nullable]).
- `password_resets` (`id`, `user_id`, `token_hash`, `expires_at`, `consumed_at` [nullable]).
- `sessions` (server-side session store, enabling targeted revocation).
- `audit_log` (per §15.7).

---

## 16. Open questions / decisions needed before build

1. **IMAP library**: **decided** — use `webklex/php-imap` (native `ext/imap` is unbundled/unmaintained as of PHP 8.4). No longer open; listed for traceability.
2. **Domains** (seeds the `domains` table + `rua=` tags): silverday.de, tourl.at, roya.at, gcgtc.com, dagatal.de, threatforge.de, clearstats.de, kioju.de, wizardscastle.de, wanyanka.de (10 domains).
3. **Alert delivery address**: set in app config (web UI). *Resolved.*
4. **GeoLite2 license key**: entered in app config (web UI). *Resolved.*
5. **Volume**: ~300 reports/day total (estimate) — trivial; the 15–30 min cron and indefinite-ish archive plan are comfortably sufficient. *Resolved.*
6. **DNSBL/RHSBL access — Spamhaus DQS required (see §11.6)**: the free Public Mirrors prohibit queries from resolvers without attributable reverse DNS, which explicitly includes major hosting/cloud networks; such queries are being cut off (returning `127.255.255.254`). The fix is a **free Data Query Service (DQS) key** (non-commercial), which suits this tool's tiny volume. Key goes in app config. *Resolved — see §11.6 for detail.*
7. **WebAuthn library**: **decided** — `web-auth/webauthn-framework` (Spomky-Labs). Full-featured and actively maintained. *Resolved.*
8. **XXE hardening — resolved (see §4.1)**: on PHP 8.0+ (libxml ≥ 2.9) external-entity substitution is **off by default**, and `libxml_disable_entity_loader()` is deprecated. Correct approach: do **not** pass `LIBXML_NOENT`/`LIBXML_DTDLOAD`; on PHP 8.4 / libxml ≥ 2.13 additionally pass the explicit `LIBXML_NO_XXE` flag as defense-in-depth. Combine with the decompression-bomb and entity-expansion caps already in §4.1. *Resolved.*
9. **DMARC report-authorization record — resolved (see §11.2)**: for a cross-domain `rua`, the *destination* domain must publish, at `<policy-domain>._report._dmarc.<destination-domain>`, a TXT record `v=DMARC1`. Concretely, with all domains reporting to a mailbox on (say) silverday.de, silverday.de must carry one record per reporting domain — e.g. `roya.at._report._dmarc.silverday.de  IN TXT "v=DMARC1"`. Without it, receivers may refuse to send. *Resolved.*

### Build tasks (not blockers)
- **Parser test corpus**: collect real aggregate reports from varied senders (Google, Microsoft, Yahoo, and smaller providers) as a regression-test set — this is how the §5 "log-and-skip" edge cases actually get shaken out. Start collecting from day one of ingestion.

### Explicitly out of scope (keep out to avoid scope creep)
Multi-tenancy/customer isolation, billing, a public API, and granular per-permission RBAC beyond the three roles. These are SaaS concerns; this tool is scoped as internal for a handful of domains. Revisit only if the scope itself changes.

---

*End of spec.*
