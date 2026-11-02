<?php

declare(strict_types=1);

use App\Help\HelpArticle;

$category = 'DMARCbis (RFC 9989/9990/9991)';

return [
    new HelpArticle(
        'dmarcbis-overview',
        'DMARC is now a Standard (DMARCbis)',
        $category,
        'In May 2026 the IETF published RFC 9989/9990/9991, obsoleting the original RFC 7489 and moving DMARC from Informational to a Proposed Standard. Existing v=DMARC1 records keep working unchanged.',
        '<p>"DMARCbis" was the working-group nickname for the effort to update DMARC from RFC 7489 (2015) to a formal Internet Standard track. That work finished in May 2026 as three RFCs: <strong>RFC 9989</strong> (the core mechanism), <strong>RFC 9990</strong> (aggregate reporting), and <strong>RFC 9991</strong> (failure reporting) — splitting what used to be one document. Together they obsolete RFC 7489.</p>'
            . '<p>This is an evolution, not a rewrite: records still start <code>v=DMARC1</code>, and the vast majority of published records keep working exactly as before with no DNS changes required. A handful of specific things did change — organizational-domain discovery, a couple of tag additions/removals, and some new optional aggregate-report fields — and this tool now surfaces those where they actually matter, rather than treating "DMARCbis" as a separate mode you opt into.</p>'
            . '<p>The current policy tags <code>np=</code>, <code>psd=</code>, and <code>t=</code> have constrained values: <code>np=</code> uses <code>none</code>, <code>quarantine</code>, or <code>reject</code>; <code>psd=</code> and <code>t=</code> use <code>y</code> or <code>n</code>. The health check flags other values for review without treating the whole record as broken.</p>'
            . '<p>See <a href="/help/article?slug=dmarcbis-org-domain">organizational domain &amp; the DNS tree walk</a> for the most conceptually significant change, and <a href="/help/article?slug=dmarcbis-deprecated-tags">deprecated tags</a> for the small cleanup most existing records are candidates for.</p>',
        ['RFC 9989', 'RFC 9990', 'RFC 9991'],
    ),
    new HelpArticle(
        'dmarcbis-org-domain',
        'Organizational domain & the DNS tree walk',
        $category,
        'Classic DMARC used the Public Suffix List to find a domain\'s "organizational domain" for policy inheritance. RFC 9989 replaces that with a DNS Tree Walk — this tool implements it, and a subdomain with no record of its own can now correctly show as covered rather than failing.',
        '<p>When a subdomain (e.g. <code>mail.example.com</code>) has no <code>_dmarc</code> record of its own, DMARC falls back to whatever its <strong>organizational domain</strong> published — typically via that domain\'s <a href="/help/article?slug=dmarc-sp">sp=</a> tag. Classic DMARC (RFC 7489) determined the organizational domain using the Public Suffix List (PSL), a community-maintained list of registrable domain suffixes.</p>'
            . '<p>RFC 9989 §4.10 replaces PSL-based lookup with a <strong>DNS Tree Walk</strong>: query <code>_dmarc.&lt;domain&gt;</code>, and if it lacks a <code>psd=</code> tag, strip the left-most label and query the parent, repeating until a record with <code>psd=n</code> or <code>psd=y</code> is found or the walk runs out of labels (capped at 8 queries as an anti-abuse measure). This tool\'s health check implements that algorithm directly rather than depending on an external PSL.</p>'
            . '<p><strong>What changed on this dashboard:</strong> previously, a domain with no <code>_dmarc</code> record of its own always showed a flat <code>fail</code> on the health check\'s DMARC row. Now, if an ancestor domain\'s record actually covers it, the row shows <code>info</code> instead — "inherits policy from organizational domain X" — since that\'s a normal, fully valid DMARC deployment pattern (most organizations only publish a record at the apex), not a problem to fix. A domain genuinely uncovered anywhere in its ancestry still shows <code>fail</code> exactly as before.</p>',
        ['RFC 9989 §4.10', 'RFC 9989 §4.10.2'],
    ),
    new HelpArticle(
        'dmarcbis-deprecated-tags',
        'Deprecated tags: pct=, rf=, ri=',
        $category,
        'RFC 9989 no longer defines pct=, rf=, or ri=. Their presence does not invalidate the other policy tags, but review the effect before removing pct<100 from an enforcement policy.',
        '<p><code>pct=</code> is the most visible change: RFC 9989 Appendix A.6 ("Removal of the \'pct\' Tag") removes it from the defined DMARC tags. It allowed a percentage of failing mail to receive the requested policy. The <code>t=</code> tag is not an equivalent percentage control: <code>t=y</code> requests test-mode handling with an expected policy one level below the published one (for example, <code>reject</code> to <code>quarantine</code>), while <code>t=n</code> is the default policy-application mode. Test mode does not affect report generation.</p>'
            . '<p><code>rf=</code> (report format) and <code>ri=</code> (report interval) — always rarely used, since <code>afrf</code>/daily were effectively the only values anyone published — simply don\'t appear in RFC 9989\'s current tag list at all.</p>'
            . '<p><strong>None of this is urgent, but check the effect before editing.</strong> The current specification requires unknown tags to be ignored, so a DMARCbis receiver may apply the full policy where a classic receiver honored a lower <code>pct=</code> value. This tool flags legacy tags informationally (never as a DMARC failure) and offers a one-click fix only when removing <code>pct=</code> cannot increase enforcement (100 or <code>p=none</code>). For a lower percentage with an enforcement policy, review the transition deliberately; <code>t=y</code> is not a percentage equivalent. Remove <code>rf=</code>/<code>ri=</code> manually during a later DNS edit.</p>',
        ['RFC 9989 Appendix A.6', 'RFC 9989 §4.7'],
    ),
    new HelpArticle(
        'dmarcbis-report-fields',
        'New report fields: envelope identifiers, discovery_method, generator',
        $category,
        'RFC 9990 aggregate reports can optionally include new identifiers and metadata, plus per-record policy override reasons — this tool captures and stores them when supplied, though they\'re not yet shown in the dashboard.',
        '<p>RFC 9990 (the DMARCbis aggregate-reporting RFC) adds a handful of optional fields to the report XML this tool already ingests and parses:</p>'
            . '<ul><li><code>generator</code> — the name/version of the software that produced the report, in <code>report_metadata</code>.</li>'
            . '<li><code>discovery_method</code> — whether the reporting receiver used <code>psl</code> or <code>treewalk</code> to find your <a href="/help/article?slug=dmarcbis-org-domain">organizational domain</a>, in <code>policy_published</code>.</li>'
            . '<li><code>envelope_from</code> / <code>envelope_to</code> — the SMTP envelope sender/recipient domains for that record, alongside the existing <a href="/help/article?slug=header-from">header_from</a>.</li>'
            . '<li><code>policy_evaluated/reason</code> — optional per-record policy override reason and comment. Its <code>type</code> may be <code>policy_test_mode</code> when the DMARC <code>t=y</code> tag exempted the message from policy application; this is not a top-level report field.</li></ul>'
            . '<p>These are optional and may be absent from classic-era reports. This tool stores metadata (<code>reports.generator</code>/<code>discovery_method</code>), envelope identifiers, and override reasons (<code>report_records.policy_override_reasons</code>) when supplied, but doesn\'t yet surface them in the dashboard.</p>',
        ['RFC 9990 §3.1.1', 'RFC 9990 §3.1.6'],
    ),
];
