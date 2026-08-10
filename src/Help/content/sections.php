<?php

declare(strict_types=1);

use App\Help\HelpArticle;

$category = 'Section guides';

return [
    new HelpArticle(
        'card-policy',
        'The Policy card',
        $category,
        'Status, the three distinct policy fields, and the deactivate/reactivate and approve-baseline actions.',
        '<p><strong>Status</strong> is whether this domain is active in every pipeline (ingestion, health checks, analysis, alerting) — Super Admins can deactivate/reactivate here, step-up gated.</p>'
            . '<p><strong>Published</strong> is <a href="/help/article?slug=policy-current-published">what DNS actually says right now</a>, read live by the health check. <strong>Approved baseline</strong> is <a href="/help/article?slug=policy-approved-baseline">the policy you\'ve explicitly signed off on</a> as known-good — click "Approve as baseline" once you\'re satisfied the published policy is correct. <strong>Target</strong> is <a href="/help/article?slug=policy-target">where you\'re working toward</a>, edited in the card below.</p>',
        [],
    ),
    new HelpArticle(
        'card-edit-target-policy',
        'The Edit target policy card',
        $category,
        'Set the p/sp levels you\'re working toward and the non-sending flag — this only records intent, it never touches DNS itself.',
        '<p>Editing this form changes <a href="/help/article?slug=policy-target">target_policy</a> only — it does not publish anything to DNS. You still make that change yourself, once the <a href="/help/article?slug=rule-r7">R7</a>/<a href="/help/article?slug=rule-r8">R8</a> recommendations (or your own judgment) say it looks safe.</p>'
            . '<p><strong>p (domain policy)</strong> and <strong>sp (subdomain policy)</strong> are explained in full at <a href="/help/article?slug=dmarc-overview">DMARC fundamentals</a> and <a href="/help/article?slug=dmarc-sp">the sp tag</a>. <strong>Non-sending domain</strong> flags a domain that should never legitimately send mail — see <a href="/help/article?slug=non-sending-domain">why that matters</a>.</p>',
        [],
    ),
    new HelpArticle(
        'card-pass-fail-chart',
        'The pass/fail volume chart',
        $category,
        'Daily message volume for this domain, split into what passed DMARC (via SPF or DKIM alignment) and what didn\'t, over the trend window.',
        '<p>Each bar is one day\'s total reported volume for this domain, split into passed (green) vs failed (red) by DMARC outcome — a message counts as passed if either SPF or DKIM authenticated <em>and</em> aligned with <a href="/help/article?slug=header-from">header_from</a>. A sudden shift is often the first visible sign of a break worth investigating in the <a href="/help/article?slug=card-sources">Sources table</a> below.</p>',
        [],
    ),
    new HelpArticle(
        'card-health-check',
        'The Health check section',
        $category,
        'The latest point-in-time DNS/network posture probe — one badge per check, independent of any report data.',
        '<p>Each item is one check\'s latest result — click its <span class="mono">?</span> for what that specific check does. The color follows <a href="/help/article?slug=hc-status-pass">pass</a>/<a href="/help/article?slug=hc-status-warn">warn</a>/<a href="/help/article?slug=hc-status-fail">fail</a>/<a href="/help/article?slug=hc-status-error">error</a>/<a href="/help/article?slug=hc-status-info">info</a> — note <code>error</code> and <code>fail</code> are deliberately different: an error means the check couldn\'t reach a conclusion, not that something\'s confirmed broken.</p>',
        [],
    ),
    new HelpArticle(
        'card-dmarcbis-readiness',
        'The DMARCbis readiness section',
        $category,
        'A checklist restating this domain\'s DMARC health check in DMARCbis (RFC 9989) terms: the deprecated pct= tag, organizational-domain coverage, and any new optional tags.',
        '<p>This card always shows three lines, reusing the same DMARC health-check result above rather than running any new check:</p>'
            . '<ul><li><strong>pct= tag</strong> — flagged if still published; see <a href="/help/article?slug=dmarcbis-deprecated-tags">deprecated tags</a>. The "Fix me" button on the health-check row above handles it.</li>'
            . '<li><strong>Organizational-domain coverage</strong> — whether this domain publishes its own record, inherits one via the <a href="/help/article?slug=dmarcbis-org-domain">DNS tree walk</a>, or has no coverage anywhere in its ancestry.</li>'
            . '<li><strong>New optional tags</strong> — whichever of <code>np=</code>/<code>psd=</code>/<code>t=</code> this domain currently publishes; see <a href="/help/article?slug=dmarcbis-overview">DMARCbis overview</a>. None set is entirely normal today.</li></ul>',
        [],
    ),
    new HelpArticle(
        'card-sources',
        'The Sources table',
        $category,
        'Every sending IP seen for this domain in the trend window, with enrichment, known/unknown labeling, volume, and DKIM/SPF pass rates.',
        '<p>Sortable by any column header, filterable by label. <strong>rDNS</strong>/<strong>ASN org</strong> come from the <a href="/help/article?slug=enrichment">enrichment pass</a>; <strong>Label</strong> is <a href="/help/article?slug=known-vs-unknown">known vs. unknown</a> classification — click a column\'s <span class="mono">?</span> for exactly what it means.</p>',
        [],
    ),
    new HelpArticle(
        'card-recommendations',
        'The Recommendations section',
        $category,
        'This domain\'s currently open R1-R12 findings, each citing the exact evidence that triggered it.',
        '<p>Findings are reconciled on every <code>bin/analyze.php</code> run — a condition that\'s no longer true auto-resolves and drops off this list. Click a rule ID\'s <span class="mono">?</span> for what specifically triggers it and what to do.</p>',
        [],
    ),
    new HelpArticle(
        'card-recent-reports',
        'The Recent reports section',
        $category,
        'The most recently ingested DMARC aggregate reports for this domain — click one to see its individual per-IP records.',
        '<p>Each row is one <a href="/help/article?slug=dmarc-aggregate-reports">aggregate report</a> received from a reporting organization, covering a specific date range. "View" opens the <a href="/help/article?slug=page-report-detail">report detail page</a> with every record it contains.</p>',
        [],
    ),
];
