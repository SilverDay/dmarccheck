<?php

declare(strict_types=1);

use App\Help\HelpArticle;

$category = 'Page guides';

return [
    new HelpArticle(
        'page-domains',
        'The Domains page',
        $category,
        'The landing page: a posture card per monitored domain, an Attention panel for what needs you today, and recent activity across every domain.',
        '<p>Each <strong>domain card</strong> shows the currently published DMARC policy, a worst-status-wins health grade, a 14-day pass/fail sparkline, and badges for any open recommendations — click a card to open that domain\'s <a href="/help/article?slug=page-domain-detail">full drill-down</a>.</p>'
            . '<p>The <strong>Attention</strong> panel surfaces the highest-severity open recommendations across every domain, so this page answers "what needs me today" without visiting each domain individually. The stats strip and <strong>Recent activity</strong> feed track ingestion health, last health-check run, and newly seen unknown senders/policy changes.</p>'
            . '<p>Admins get an <strong>Add domain</strong> form at the bottom — onboarding runs a full health check immediately (spec §11.1), so a new domain gets a baseline right away rather than waiting for the next scheduled run.</p>',
        [],
    ),
    new HelpArticle(
        'page-domain-detail',
        'The domain drill-down page',
        $category,
        'Everything about one domain: policy status and controls, the pass/fail trend, health-check results, per-source-IP traffic, open recommendations, and recent reports.',
        '<p>The <strong>Policy</strong> card shows the three distinct policy fields — <a href="/help/article?slug=policy-current-published">published</a>, <a href="/help/article?slug=policy-approved-baseline">approved baseline</a>, and <a href="/help/article?slug=policy-target">target</a> — plus (role-permitting) the deactivate/reactivate and approve-baseline actions and an editable target policy.</p>'
            . '<p>The <strong>Sources</strong> table lists every sending IP seen in the last 30 days with rDNS/ASN enrichment, its <a href="/help/article?slug=known-vs-unknown">known/unknown</a> label, volume, and DKIM/SPF pass rates — sortable and filterable by label. <strong>Health check</strong> shows the latest DNS/network posture probe results. <strong>Recommendations</strong> lists this domain\'s open R1-R12 findings. <strong>Recent reports</strong> links to the raw per-record view for any ingested report.</p>',
        [],
    ),
    new HelpArticle(
        'page-report-detail',
        'The report detail page',
        $category,
        'One ingested DMARC report, broken down to the individual source-IP records it contains.',
        '<p>Shows one report\'s metadata (reporting organization, report ID, period covered) and every <a href="/help/article?slug=dmarc-aggregate-reports">record</a> it contains — source IP, message count, disposition applied, and the raw DKIM/SPF/alignment results reported for that IP, expandable to the underlying <code>auth_results</code> rows when present.</p>',
        [],
    ),
    new HelpArticle(
        'page-allowlist',
        'The Allowlist page',
        $category,
        'Add or remove known-senders rules — IP/CIDR ranges you trust as legitimate senders, scoped to one domain or applied globally.',
        '<p>Each rule is an IP or CIDR range with a label and either a specific domain or "All domains" (a global rule). There\'s no edit form — changing a rule is delete-then-re-add, which keeps the audit trail unambiguous.</p>'
            . '<p>A rule doesn\'t take effect instantly: it\'s picked up the next time enrichment or the recommendation engine runs, since this page only writes the table. See <a href="/help/article?slug=known-senders-allowlist">how the allowlist works</a> for more.</p>',
        [],
    ),
    new HelpArticle(
        'page-users',
        'The Users page',
        $category,
        'Super-admin-only account management: invite, change role, disable/re-enable, delete, force logout, trigger a password reset, or reset MFA.',
        '<p>Every action here is step-up-gated (re-verify with your current password, or a passkey prompt at the moment you click) and audit-logged. <strong>Reset MFA</strong> additionally requires ticking "Identity verified out-of-band" — a hard requirement, not just a warning, since clearing someone\'s MFA is a common social-engineering target.</p>'
            . '<p>The app always keeps at least one active super admin — an action that would leave zero is refused rather than silently allowed.</p>',
        [],
    ),
    new HelpArticle(
        'page-audit-log',
        'The Audit log page',
        $category,
        'A read-only, Super-Admin-only feed of every recorded governance action — who did what, and when.',
        '<p>Every sensitive action across the app (domain onboarding/deactivation, policy changes, user invites/role changes/MFA resets, allowlist edits, retention pruning) writes an entry here. This page is read-only — it exists to close the governance loop, not to take action from.</p>',
        [],
    ),
    new HelpArticle(
        'page-security',
        'The Security settings page',
        $category,
        'Your own account: change password, set up or remove an authenticator app and recovery codes, add or remove passkeys.',
        '<p>Reach this page any time by clicking your email in the top-right corner. Sensitive changes here (removing your authenticator app, regenerating recovery codes, removing a passkey) are step-up-gated the same way admin actions are — if you\'re passkey-only, the browser\'s native passkey prompt appears at the moment you submit, not as a separate earlier step.</p>',
        [],
    ),
];
