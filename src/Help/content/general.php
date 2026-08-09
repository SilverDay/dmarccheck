<?php

declare(strict_types=1);

use App\Help\HelpArticle;

$category = 'General / operational';

return [
    new HelpArticle(
        'known-vs-unknown',
        'Known vs. unknown sender classification',
        $category,
        'Whether a source IP is "known" changes what a finding means, not just how severe it is — a known sender\'s auth failure is a config fix; an unknown sender\'s is a possible spoofing attempt.',
        '<p>Every source IP in a report is classified as known or unknown by matching it against the <a href="/help/article?slug=known-senders-allowlist">known-senders allowlist</a>, scoped per domain: rules that apply globally (no specific domain) or to that exact domain are checked by CIDR match, in the order they were added, first match wins; anything left over is unknown.</p>'
            . '<p>This distinction drives which recommendation rules can even fire — <a href="/help/article?slug=rule-r1">R1</a>-<a href="/help/article?slug=rule-r3">R3</a> (known-sender hygiene: fix your SPF/DKIM/alignment) only apply to known senders, while <a href="/help/article?slug=rule-r5">R5</a>/<a href="/help/article?slug=rule-r6">R6</a> (possible spoofing) only apply to unknown ones. The same raw auth-failure data means something very different depending on which bucket the sender falls in.</p>',
        [],
    ),
    new HelpArticle(
        'enrichment',
        'IP enrichment: rDNS, ASN, labeling',
        $category,
        'A background pass that labels every source IP seen in reports as known infrastructure, a recognized email service provider, or unknown — using reverse DNS and network ownership, not just the allowlist.',
        '<p>Enrichment runs separately from ingestion, on a schedule, over every source IP that\'s appeared in a report. It resolves reverse DNS and, where a GeoLite2 database is available, the owning network (ASN), then assigns a label by precedence: an exact <a href="/help/article?slug=known-senders-allowlist">known-senders</a> CIDR match wins first, then a conservative built-in list of known email-service-provider ASNs, then <code>unknown</code> if neither matched.</p>'
            . '<p>This label is what the domain page\'s source table and the alerting digest\'s unknown-volume check both read — it\'s informational/global, distinct from the domain-scoped matching the recommendation engine uses for R1-R12 (see <a href="/help/article?slug=known-vs-unknown">known vs. unknown</a>).</p>',
        [],
    ),
    new HelpArticle(
        'known-senders-allowlist',
        'The known-senders allowlist',
        $category,
        'A manually maintained list of IP/CIDR ranges you trust as legitimate senders for a domain (or globally) — edited on the Allowlist page, Admin tier.',
        '<p>Add a rule with an IP or CIDR range, a label, and either a specific domain or "All domains" (a global rule, applied when no domain is specified). There\'s no update form — editing a rule is delete-then-re-add, since that keeps the audit trail unambiguous about what changed.</p>'
            . '<p>A new or changed rule takes effect the next time enrichment or the recommendation engine runs, not instantly — this page only writes the table.</p>',
        [],
    ),
    new HelpArticle(
        'ingestion-pipeline',
        'How reports flow from mailbox to dashboard',
        $category,
        'Poll the configured mailbox over IMAP, decompress and sniff the format, parse it, store it, then archive the original file and file the email away — all idempotent, so re-running never double-counts.',
        '<p>The pipeline: poll the IMAP mailbox at <a href="/help/article?slug=dmarc-rua">rua=</a> → decompress the attachment (bounded, to defend against a <a href="/help/article?slug=decompression-bomb">decompression bomb</a>) → detect whether it\'s DMARC XML or TLS-RPT JSON → parse it → store it in the database. A successfully processed message is archived (compressed, named by content hash — never by the original filename, which is attacker-controlled) and moved to a "done" mailbox folder; a failure is moved to a "failed" folder for manual review rather than silently dropped.</p>'
            . '<p>Re-running ingestion is safe and idempotent — see <a href="/help/article?slug=report-dedup">how duplicate ingestion is prevented</a>.</p>',
        [],
    ),
    new HelpArticle(
        'report-dedup',
        'How duplicate report ingestion is prevented',
        $category,
        'Enforced at the database layer with a content hash and a uniqueness constraint — not application logic — so re-running ingestion twice never double-counts a report.',
        '<p>Every raw report file\'s hash is recorded, and the combination of (domain, reporting organization, report ID) is a database uniqueness constraint. If ingestion runs twice over the same mailbox — intentionally, or because a cron overlapped — the second pass simply can\'t insert the same report again; the database itself is what prevents duplication, not a check in the ingestion code, which is a more reliable guarantee.</p>',
        [],
    ),
    new HelpArticle(
        'decompression-bomb',
        'What a decompression bomb is (and how this tool defends against it)',
        $category,
        'A tiny compressed file crafted to expand to an enormous size when decompressed — a classic denial-of-service technique this tool has to defend against, since the report-submission address is public DNS anyone can mail.',
        '<p>Because a domain\'s <a href="/help/article?slug=dmarc-rua">rua=</a> address is published in public DNS, anyone — not just legitimate mail receivers — can send it an attachment. A hostile actor could craft a small gzip/zip file that expands to gigabytes when decompressed, exhausting memory or disk. This tool inflates gzip data through a bounded stream in small chunks, checking the size after every chunk so a bomb is caught mid-stream rather than after the damage is already done, and caps both the count and per-entry size of zip archive entries before or while reading them.</p>',
        [],
    ),
];
