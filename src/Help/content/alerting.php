<?php

declare(strict_types=1);

use App\Help\HelpArticle;

$category = 'Alerting';

return [
    new HelpArticle(
        'alert-heartbeat',
        'Heartbeat alert',
        $category,
        'Fires when a domain hasn\'t received any reports for longer than the configured window — the dead-man\'s-switch for a stalled ingestion pipeline or a receiver that stopped reporting.',
        '<p>The heartbeat check flags any active domain with no reports received in the last N days (configurable). For a domain that has never received a report at all, it falls back to comparing against the domain\'s onboarding date instead, so a brand-new domain doesn\'t false-positive on day one just because reports haven\'t arrived yet.</p>'
            . '<p>A heartbeat firing usually means either your IMAP polling has broken, or a major receiver has stopped sending you reports — worth checking the domain page\'s ingestion-health indicator first.</p>',
        [],
    ),
    new HelpArticle(
        'alert-policy-drift',
        'Policy drift alert',
        $category,
        'Fires when the domain\'s live DNS DMARC record no longer matches the policy you explicitly approved as the baseline — the same condition as recommendation rule R9, checked independently every day.',
        '<p>This is the identical condition <a href="/help/article?slug=rule-r9">R9</a> checks, but computed directly against the domain\'s live <a href="/help/article?slug=policy-current-published">current_published_policy</a> vs <a href="/help/article?slug=policy-approved-baseline">approved_baseline_policy</a> rather than depending on the recommendation engine having already run — so the daily alerting digest keeps working standalone even if <code>bin/analyze.php</code> hasn\'t executed.</p>',
        [],
    ),
    new HelpArticle(
        'alert-unknown-volume',
        'Unknown-volume alert',
        $category,
        'Fires when any single unclassified sender exceeds a volume threshold — a lightweight daily tripwire for a spike from an unrecognized source.',
        '<p>Checks per-source-IP volume against a threshold using the same plain <code>ip_enrichment.label</code> classification used across the dashboard (not the domain-scoped allowlist matching the recommendation engine uses) — deliberately a lighter-weight, faster daily check than the full R5/R6 analysis, meant to catch an obvious spike quickly rather than replace the deeper rule engine.</p>',
        [],
    ),
    new HelpArticle(
        'alert-pass-rate',
        'Pass-rate regression alert',
        $category,
        'Fires when today\'s DMARC pass rate has dropped meaningfully below a trailing baseline average — an early signal something broke, even before any single rule fires.',
        '<p>Compares today\'s pass rate against a trailing baseline window\'s average, only when both windows have enough sample volume to be statistically meaningful (skipped below a configured minimum sample size in either window, to avoid noisy alerts on a low-traffic domain). A regression here can be the first sign of a broken SPF/DKIM change before the underlying cause shows up as a specific recommendation.</p>',
        [],
    ),
];
