<?php

declare(strict_types=1);

use App\Help\HelpArticle;

$category = 'Recommendation rules';

return [
    new HelpArticle(
        'rule-r1',
        'R1 — Known sender, SPF fail, alignment OK',
        $category,
        'Low severity. A source you\'ve already labeled as a known sender is failing SPF specifically, but DKIM or alignment still make the message pass DMARC overall.',
        '<p><strong>Triggers when:</strong> a source IP matched by the <a href="/help/article?slug=known-vs-unknown">known-senders allowlist</a> (and not already recognized as a known forwarder, which is R12\'s case instead) shows SPF failing while there\'s no accompanying SPF alignment problem — i.e. the sender is legitimate but its SPF setup for this specific path needs attention.</p>'
            . '<p><strong>What to do:</strong> check whether this sending platform is included in your SPF record (<code>include:</code>) — a missing or stale include is the most common cause. Low severity because DKIM is typically still covering the message.</p>',
        [],
    ),
    new HelpArticle(
        'rule-r2',
        'R2 — Known sender, DKIM fail, alignment OK',
        $category,
        'Low severity. A known sender is failing DKIM specifically, while SPF or alignment still keep the message passing DMARC overall.',
        '<p><strong>Triggers when:</strong> a known-sender source shows DKIM failing with no accompanying DKIM alignment problem.</p>'
            . '<p><strong>What to do:</strong> a DKIM fail from an otherwise-legitimate known sender usually means a signing key was rotated without the old one being fully retired, or the sending platform\'s DKIM setup for your domain broke recently — check with the sending platform\'s DKIM/DNS setup for your domain.</p>',
        [],
    ),
    new HelpArticle(
        'rule-r3',
        'R3 — Known sender, alignment failure',
        $category,
        'Low severity. A known sender\'s SPF and/or DKIM mechanism itself passed, but the authenticated domain doesn\'t align with your visible From: address.',
        '<p><strong>Triggers when:</strong> for a known-sender source, the underlying SPF or DKIM check technically passed, but <a href="/help/article?slug=dmarc-alignment">alignment</a> against header_from failed — the most common cause is a third-party platform sending on your behalf without being configured to sign/send as your own domain.</p>'
            . '<p><strong>What to do:</strong> configure the sending platform to use your domain for DKIM signing and/or the envelope sender, rather than its own, so alignment succeeds going forward.</p>',
        [],
    ),
    new HelpArticle(
        'rule-r4',
        'R4 — SPF lookup limit exceeded',
        $category,
        'Medium severity, domain-wide. A live SPF lookup count against your published record exceeds RFC 7208\'s 10-DNS-lookup limit.',
        '<p><strong>Triggers when:</strong> a live SPF evaluation (reusing the same health-check logic that probes your record) counts more than 10 DNS-querying mechanisms — see <a href="/help/article?slug=spf-lookup-limit">the lookup limit</a>. Every receiver evaluating your SPF record will hit <a href="/help/article?slug=spf-result-permerror">permerror</a>, not just this tool.</p>'
            . '<p><strong>What to do:</strong> consolidate or remove <code>include:</code> mechanisms, or use a provider\'s "SPF flattening" service, to bring the count back under 10.</p>',
        ['RFC 7208 §4.6.4'],
    ),
    new HelpArticle(
        'rule-r5',
        'R5 — Unknown source, sustained auth failures above threshold',
        $category,
        'High severity. A source not on your allowlist is failing both SPF and DKIM, in volume, over the standard analysis window.',
        '<p><strong>Triggers when:</strong> an <a href="/help/article?slug=known-vs-unknown">unknown</a> source IP has a volume of messages failing both SPF and DKIM above the configured threshold, within the standard analysis window.</p>'
            . '<p><strong>What to do:</strong> investigate the source (rDNS/ASN enrichment on the domain page\'s source table is the starting point). This is deliberately phrased as "investigate," not "block" — a domain spoofing your name toward a third party\'s inbox isn\'t necessarily hitting your own mail server, so blocking based on aggregate-report data alone isn\'t justified; only act on traffic you\'ve also observed on your own MX.</p>',
        [],
    ),
    new HelpArticle(
        'rule-r6',
        'R6 — Unknown source, sustained spoofing campaign',
        $category,
        'High severity. The same pattern as R5, but spanning several distinct report days — evidence of an ongoing campaign rather than a one-off spike.',
        '<p><strong>Triggers when:</strong> the R5 condition (unknown source, both SPF and DKIM failing, above threshold) persists across at least the configured minimum number of distinct report days in the longer sustained-analysis window, rather than appearing in a single report.</p>'
            . '<p><strong>What to do:</strong> the same investigate-don\'t-block guidance as R5 applies, with added urgency — a sustained pattern across multiple days is stronger evidence of an active, ongoing spoofing campaign rather than a transient misconfiguration somewhere.</p>',
        [],
    ),
    new HelpArticle(
        'rule-r7',
        'R7 — Safe to advance policy to quarantine',
        $category,
        'Medium severity. Currently at p=none with no known-sender authentication failures observed — the data suggests it\'s safe to move to quarantine.',
        '<p><strong>Triggers when:</strong> the domain\'s <a href="/help/article?slug=policy-current-published">currently published policy</a> is <a href="/help/article?slug=dmarc-policy-none">p=none</a>, the <a href="/help/article?slug=policy-target">target policy</a> calls for something stricter, and no known senders showed total authentication failure in the analysis window — i.e. every legitimate sender you know about would have survived enforcement.</p>'
            . '<p><strong>What to do:</strong> this is a green light, not an automatic change — review the evidence, then advance <code>p=</code> to <code>quarantine</code> yourself via the domain page\'s target-policy editor. This app never edits DNS or auto-advances a policy on its own.</p>',
        [],
    ),
    new HelpArticle(
        'rule-r8',
        'R8 — Safe to advance policy to reject',
        $category,
        'Medium severity. Currently at p=quarantine with no known-sender authentication failures observed — the data suggests it\'s safe to move to reject.',
        '<p><strong>Triggers when:</strong> the same shape as <a href="/help/article?slug=rule-r7">R7</a>, but starting from <a href="/help/article?slug=dmarc-policy-quarantine">p=quarantine</a> instead of <code>p=none</code> — the step up to the strongest available policy.</p>'
            . '<p><strong>What to do:</strong> same as R7 — review the evidence, then deliberately advance the target policy to <code>reject</code> yourself when confident. This rule only fires when your own <a href="/help/article?slug=policy-target">target policy</a> calls for reject specifically — under <a href="/help/article?slug=dmarcbis-overview">DMARCbis</a> (RFC 9989 §3.2.9), quarantine is also a fully valid, permanent "Enforcement" state, so staying there is a legitimate choice, not something this rule treats as unfinished.</p>',
        [],
    ),
    new HelpArticle(
        'rule-r9',
        'R9 — Published policy drifted from approved baseline',
        $category,
        'High severity. The domain\'s live DNS DMARC record no longer matches the policy you explicitly approved as the known-good baseline.',
        '<p><strong>Triggers when:</strong> the normalized <a href="/help/article?slug=policy-current-published">current_published_policy</a> (read live from DNS) differs from the <a href="/help/article?slug=policy-approved-baseline">approved_baseline_policy</a> you deliberately set — and only once a baseline actually exists, since there\'s nothing to drift from before that. This is the same condition the daily alerting digest\'s policy-drift check watches, computed independently so it doesn\'t depend on this rule engine having run.</p>'
            . '<p><strong>What to do:</strong> a mismatch means either someone changed the DNS record outside your normal process, or DNS itself was tampered with — treat it as worth investigating promptly, not routine drift. If the change was intentional, re-approve the new policy as the baseline once you\'ve confirmed it.</p>',
        [],
    ),
    new HelpArticle(
        'rule-r10',
        'R10 — Traffic seen on a domain marked non-sending',
        $category,
        'Medium severity. A domain flagged as never sending mail is showing real report volume — either the flag is stale, or someone is spoofing it.',
        '<p><strong>Triggers when:</strong> a domain with <a href="/help/article?slug=non-sending-domain">non_sending</a> set to true has non-zero traffic (<code>total_count</code>) observed in the analysis window.</p>'
            . '<p><strong>What to do:</strong> if the domain has genuinely started sending mail, clear the <code>non_sending</code> flag via the domain page. If it hasn\'t, the traffic is spoofed — this is a strong argument for setting <code>p=reject</code> on a domain that should have zero legitimate senders to break.</p>',
        [],
    ),
    new HelpArticle(
        'rule-r11',
        'R11 — No sp= while subdomain spoofing observed',
        $category,
        'Medium severity. The domain hasn\'t published a subdomain policy, and reports show a strict subdomain being spoofed in header_from.',
        '<p><strong>Triggers when:</strong> the domain\'s DMARC record has no <a href="/help/article?slug=dmarc-sp">sp=</a> tag, and reports show a subdomain (strictly, not the organizational domain itself) appearing in header_from with total authentication failure.</p>'
            . '<p><strong>What to do:</strong> publish an explicit <code>sp=</code> — usually <code>reject</code> if the domain has no legitimate subdomain-sending traffic — to close off spoofing of subdomains that would otherwise silently inherit whatever the main <code>p=</code> allows.</p>',
        [],
    ),
    new HelpArticle(
        'rule-r12',
        'R12 — Known forwarder, expected SPF-fail signature (informational)',
        $category,
        'Informational, no action needed. A known mail forwarder is showing the exact SPF-fail pattern forwarding always produces — this is expected, not a problem.',
        '<p><strong>Triggers when:</strong> a source explicitly labeled as a known forwarder in the allowlist shows an SPF-only failure — the textbook signature of <a href="/help/article?slug=spf-alignment">forwarded mail</a>, where the forwarder\'s envelope sender doesn\'t align with the original header_from, but the original DKIM signature usually still survives and covers the message.</p>'
            . '<p><strong>What to do:</strong> nothing — this rule exists specifically so a legitimate, already-identified forwarder doesn\'t get flagged under R1/R5 alongside genuine problems. It\'s informational, explicitly "no action," not a hidden warning.</p>',
        [],
    ),
];
