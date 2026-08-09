<?php

declare(strict_types=1);

use App\Help\HelpArticle;

$category = 'Domain policy concepts';

return [
    new HelpArticle(
        'policy-current-published',
        'Current published policy',
        $category,
        'What the domain\'s DMARC record actually says in live DNS right now, auto-read by the health check — not something you edit directly in this tool.',
        '<p><code>current_published_policy</code> is updated automatically whenever the DMARC health check runs, by reading the domain\'s <code>_dmarc</code> TXT record live from DNS. It reflects reality, not intent — if someone edits DNS outside this tool, this field changes on the next health-check run, which is exactly what the <a href="/help/article?slug=rule-r9">policy-drift recommendation</a> and <a href="/help/article?slug=alert-policy-drift">alert</a> watch for.</p>',
        [],
    ),
    new HelpArticle(
        'policy-approved-baseline',
        'Approved baseline policy',
        $category,
        'The policy you\'ve explicitly signed off on as the domain\'s known-good state — set only by a deliberate admin action, never automatically.',
        '<p><code>approved_baseline_policy</code> only ever changes when an admin clicks "Approve as baseline" on the domain page. It exists so drift detection has something meaningful to compare against — without an explicit human decision about what "correct" looks like, any DNS change would be indistinguishable from an intended update. This tool refuses to seed a baseline automatically or silently, even at onboarding — see <a href="/help/article?slug=policy-approve-baseline-action">why approving is a deliberate action</a>.</p>',
        [],
    ),
    new HelpArticle(
        'policy-target',
        'Target policy',
        $category,
        'Where you want the domain\'s DMARC policy to eventually be — the goal this tool\'s R7/R8 recommendations check readiness against, editable directly by an admin.',
        '<p><code>target_policy</code> is the <code>p=</code>/<code>sp=</code> combination you\'re working toward, editable directly on the domain page. It\'s independent of what\'s actually published in DNS (<a href="/help/article?slug=policy-current-published">current_published_policy</a>) — setting a target doesn\'t change DNS itself; you still make that change yourself once the recommendation engine confirms it looks safe.</p>',
        [],
    ),
    new HelpArticle(
        'policy-approve-baseline-action',
        'Why approving the baseline is a deliberate action',
        $category,
        'This tool never auto-seeds a baseline policy, even when onboarding a brand-new domain — an admin has to explicitly click "Approve as baseline" once a published policy has actually been observed.',
        '<p>A baseline that gets set automatically defeats its own purpose — if the tool just copied whatever DNS says into the baseline the moment it\'s observed, an attacker\'s tampered record would become "approved" the instant it\'s read, and drift detection would never fire. Approving is refused entirely until a <a href="/help/article?slug=policy-current-published">published policy</a> has actually been observed at least once (so there\'s something real to approve), and it\'s always a deliberate, audit-logged admin click.</p>',
        [],
    ),
    new HelpArticle(
        'non-sending-domain',
        'Non-sending domain flag',
        $category,
        'Mark a domain as never legitimately sending mail — any report traffic for it is then, by definition, spoofed, which is exactly what recommendation R10 watches for.',
        '<p>Some domains exist only to receive mail, or are parked/unused entirely — they should never appear as a sender in anyone\'s DMARC reports. Flagging <code>non_sending</code> on the domain page tells this tool that assumption, so <a href="/help/article?slug=rule-r10">R10</a> can flag any observed traffic as spoofing rather than silently ignoring it as ordinary activity.</p>'
            . '<p>A non-sending domain is also usually a strong <code>p=reject</code> candidate — there\'s no legitimate traffic that enforcement could break.</p>',
        [],
    ),
];
