<?php

declare(strict_types=1);

use App\Help\HelpArticle;

$category = 'DMARC fundamentals';

return [
    new HelpArticle(
        'dmarc-overview',
        'What is DMARC?',
        $category,
        'DMARC lets a domain owner publish a policy telling receiving mail servers what to do with messages that fail SPF/DKIM authentication, and asks for reports back.',
        '<p>DMARC (Domain-based Message Authentication, Reporting and Conformance, RFC 7489, updated by <a href="/help/article?slug=dmarcbis-overview">RFC 9989/9990/9991</a>) is a DNS TXT record published at <code>_dmarc.yourdomain.com</code>. It does two things: sets a policy (<code>p=</code>) telling receivers what to do with mail claiming to be from your domain that fails authentication, and requests aggregate reports (<code>rua=</code>) — daily summaries of who is sending mail as your domain and whether it passed.</p>'
            . '<p>DMARC itself does not authenticate anything directly. It relies on SPF and DKIM, and adds one more requirement on top: <a href="/help/article?slug=dmarc-alignment">alignment</a> between the authenticated domain and the visible <a href="/help/article?slug=header-from">From: address</a>.</p>'
            . '<p>This tool exists to make the <a href="/help/article?slug=dmarc-aggregate-reports">aggregate reports</a> DMARC generates actually readable, and to help you move a domain safely from <code>p=none</code> toward <code>p=reject</code> without breaking legitimate mail.</p>'
            . '<p><strong>If the health check reports "no DMARC record found":</strong> publish one at <code>_dmarc.yourdomain.com</code>. A safe starting point that only monitors, changing nothing about delivery: <code class="rec-evidence">v=DMARC1; p=none; rua=mailto:you@yourdomain.com</code> — see <a href="/help/article?slug=dmarc-policy-none">p=none</a> for why that\'s the right first step. Once a domain is already onboarded here, set that <code>rua=</code> address to this tool\'s own mailbox so its reports actually reach the dashboard — see the domain page\'s "Cross-domain report authorization" card for the exact address and any extra DNS record needed.</p>'
            . '<p><strong>If the health check instead shows "inherits policy from organizational domain X":</strong> that\'s not a problem — see <a href="/help/article?slug=dmarcbis-org-domain">organizational domain &amp; the DNS tree walk</a> for what that means and why it\'s a normal, fully valid DMARC deployment pattern.</p>',
        ['RFC 7489'],
    ),
    new HelpArticle(
        'dmarc-policy-none',
        'p=none — monitoring only',
        $category,
        'The weakest DMARC policy: failing mail is delivered exactly as if no DMARC record existed. You still get reports, but nothing is blocked.',
        '<p><code>p=none</code> tells receivers to take no enforcement action based on DMARC results — mail that fails SPF/DKIM/alignment is delivered normally. It is the standard starting point: it turns on <a href="/help/article?slug=dmarc-aggregate-reports">aggregate reporting</a> so you can see who is actually sending as your domain before you risk blocking anything.</p>'
            . '<p>A domain should not stay at <code>p=none</code> indefinitely — it provides visibility but zero anti-spoofing protection. This tool\'s R7/R8 recommendations flag when the observed data looks safe to advance to <code>quarantine</code> or <code>reject</code>.</p>',
        ['RFC 7489 §6.3'],
    ),
    new HelpArticle(
        'dmarc-policy-quarantine',
        'p=quarantine — send failing mail to spam',
        $category,
        'Mail that fails DMARC is not rejected outright — receivers are asked to treat it as suspicious, typically by routing it to spam/junk.',
        '<p><code>p=quarantine</code> asks receiving mail servers to deliver DMARC-failing mail to the recipient\'s spam folder rather than the inbox, instead of rejecting it outright. It is the usual middle step between <a href="/help/article?slug=dmarc-policy-none">p=none</a> and <a href="/help/article?slug=dmarc-policy-reject">p=reject</a>, giving you a chance to catch legitimate senders you missed before enforcement gets stricter.</p>'
            . '<p><code>pct=</code> can apply this to only a percentage of failing mail during rollout — see the <a href="/help/article?slug=dmarc-pct">pct</a> article.</p>',
        ['RFC 7489 §6.3'],
    ),
    new HelpArticle(
        'dmarc-policy-reject',
        'p=reject — discard failing mail',
        $category,
        'The strongest DMARC policy: mail that fails DMARC authentication is rejected during the SMTP transaction and never delivered.',
        '<p><code>p=reject</code> asks receivers to refuse DMARC-failing mail outright, typically with an SMTP-level bounce, rather than delivering or quarantining it. This is the strongest available protection for a domain that wants full anti-spoofing coverage — it is only safe to set once you have confirmed, from real aggregate report data, that every legitimate sending source for the domain is passing SPF or DKIM with alignment.</p>'
            . '<p>Going to <code>p=reject</code> before every legitimate sender (billing systems, marketing platforms, forwarders) is accounted for will silently drop real mail — this is why this tool\'s approve-baseline/target-policy workflow exists, rather than editing the DNS record blind.</p>'
            . '<p>Note: RFC 9989 (<a href="/help/article?slug=dmarcbis-overview">DMARCbis</a>) §3.2.9 defines "Enforcement" as any policy that isn\'t <code>p=none</code> — <a href="/help/article?slug=dmarc-policy-quarantine">quarantine</a> counts equally with reject as a genuine enforcement state, not just a waypoint on the way here. Reject remains the strongest option, but a domain that settles permanently on quarantine for a lighter-touch posture isn\'t doing DMARC "wrong."</p>',
        ['RFC 7489 §6.3'],
    ),
    new HelpArticle(
        'dmarc-pct',
        'pct= — gradual rollout percentage',
        $category,
        'The pct tag applies your quarantine/reject policy to only a percentage of failing mail, letting you roll out enforcement gradually.',
        '<p><code>pct=</code> (0-100, default 100) tells receivers to apply the DMARC policy (<code>quarantine</code> or <code>reject</code>) to only that percentage of messages that would otherwise be affected; the rest fall back to the next weaker policy. For example <code>p=reject; pct=25</code> rejects roughly a quarter of failing mail and lets the other three quarters through, so you can watch for unexpected breakage before committing fully.</p>'
            . '<p><code>pct=</code> has no effect at <code>p=none</code>, since there is no enforcement to apply partially.</p>'
            . '<p>Under <a href="/help/article?slug=dmarcbis-overview">DMARCbis</a> (RFC 9989), <code>pct=</code> was removed as a defined tag — see <a href="/help/article?slug=dmarcbis-deprecated-tags">deprecated tags</a> for what replaces it. This isn\'t urgent: a record still publishing <code>pct=</code> keeps working exactly as before, and this tool\'s health check offers a one-click DNS fix to drop it whenever you\'re ready.</p>',
        ['RFC 7489 §6.3'],
    ),
    new HelpArticle(
        'dmarc-sp',
        'sp= — subdomain policy',
        $category,
        'sp lets a domain set a different DMARC policy specifically for its subdomains, overriding the main p= tag for anything not exactly the organizational domain.',
        '<p><code>sp=</code> overrides <code>p=</code> for mail claiming to be from any subdomain of the published domain (e.g. <code>mail.example.com</code>, <code>newsletter.example.com</code>) that doesn\'t itself publish its own DMARC record. Without <code>sp=</code>, subdomains inherit <code>p=</code>.</p>'
            . '<p>Leaving <code>sp=</code> unset while an attacker spoofs a plausible-looking subdomain that never sends real mail is exactly the gap this tool\'s R11 recommendation watches for — publishing <code>sp=reject</code> on a domain that has no legitimate subdomain traffic is usually safe and closes off a common spoofing vector.</p>'
            . '<p>Under <a href="/help/article?slug=dmarcbis-overview">DMARCbis</a> (RFC 9989), a new <code>np=</code> tag sets a policy specifically for subdomains that <strong>don\'t exist</strong> in DNS at all — distinct from <code>sp=</code>, which covers subdomains that exist but publish no record of their own. It\'s optional and defaults to whatever <code>sp=</code>/<code>p=</code> already resolve to; no current domain in this tool needs to set it to stay correctly configured.</p>',
        ['RFC 7489 §6.3'],
    ),
    new HelpArticle(
        'dmarc-adkim',
        'adkim= — DKIM alignment mode',
        $category,
        'adkim controls how strictly the DKIM signing domain must match the visible From: domain: r (relaxed, default) allows a matching organizational domain; s (strict) requires an exact match.',
        '<p><code>adkim=r</code> (relaxed, the default) accepts DKIM alignment as long as the signing domain (<code>d=</code> in the DKIM-Signature header) shares the same organizational/registrable domain as <a href="/help/article?slug=header-from">header_from</a> — e.g. <code>mail.example.com</code> aligns with <code>example.com</code>. <code>adkim=s</code> (strict) requires the two to match exactly.</p>'
            . '<p>Relaxed mode is almost always the right default; strict mode is a rarely-needed hardening step that will break legitimate mail from subdomains you haven\'t accounted for.</p>',
        ['RFC 7489 §6.3'],
    ),
    new HelpArticle(
        'dmarc-aspf',
        'aspf= — SPF alignment mode',
        $category,
        'aspf controls how strictly the SPF-authenticated domain must match the visible From: domain: r (relaxed, default) allows a matching organizational domain; s (strict) requires an exact match.',
        '<p><code>aspf=r</code> (relaxed, the default) accepts SPF alignment as long as the domain SPF authenticated (the <a href="/help/article?slug=spf-alignment">MAIL FROM domain</a>) shares the same organizational/registrable domain as <a href="/help/article?slug=header-from">header_from</a>. <code>aspf=s</code> (strict) requires an exact match — meaning a sending domain like <code>bounce.example.com</code> would no longer align with a From: of <code>example.com</code>.</p>',
        ['RFC 7489 §6.3'],
    ),
    new HelpArticle(
        'dmarc-rua',
        'rua= — aggregate report destination',
        $category,
        'rua is the mailto: address (or addresses) where receivers send the daily aggregate reports this tool ingests and parses.',
        '<p><code>rua=</code> lists one or more <code>mailto:</code> URIs that receiving mail servers send DMARC aggregate reports to, roughly daily. This tool\'s ingestion pipeline polls exactly that mailbox — see <a href="/help/article?slug=ingestion-pipeline">how reports flow from mailbox to dashboard</a>.</p>'
            . '<p>If <code>rua=</code> points at a mailbox on a <em>different</em> domain than the one being monitored, that destination domain must separately authorize receiving reports for this domain via a <code>&lt;policy&gt;._report._dmarc.&lt;destination&gt;</code> TXT record — this is exactly what the domain page\'s "Cross-domain report authorization" card generates for you.</p>',
        ['RFC 7489 §7.1'],
    ),
    new HelpArticle(
        'dmarc-alignment',
        'What "alignment" means',
        $category,
        'Alignment is DMARC\'s extra requirement on top of SPF/DKIM passing: the domain that was actually authenticated must match the domain shown to the recipient in the From: header.',
        '<p>SPF and DKIM each authenticate a domain, but not necessarily the one shown in the visible <a href="/help/article?slug=header-from">From:</a> header a recipient sees. SPF authenticates the envelope MAIL FROM domain; DKIM authenticates whatever domain signed the message (<code>d=</code>). DMARC requires at least one of those to also <strong>align</strong> — match (exactly or by organizational domain, per <a href="/help/article?slug=dmarc-adkim">adkim</a>/<a href="/help/article?slug=dmarc-aspf">aspf</a>) — with header_from.</p>'
            . '<p>This is why a message can show <code>spf=pass</code> and <code>dkim=pass</code> in a raw report and still fail DMARC overall: both mechanisms authenticated a real domain, just not the one in From:. This tool\'s R3 recommendation specifically flags known senders whose auth mechanism passed but alignment didn\'t.</p>',
        ['RFC 7489 §3.1'],
    ),
    new HelpArticle(
        'dmarc-aggregate-reports',
        'What aggregate reports contain',
        $category,
        'Daily XML summaries, one row per distinct sending IP, with SPF/DKIM/disposition results — never individual message content, subject lines, or recipients.',
        '<p>A DMARC aggregate report is an XML document a receiving mail server sends roughly daily, summarizing every message it saw claiming to be from your domain during that window, grouped by <strong>source IP</strong>. Each row (this tool stores it as one <code>report_records</code> row) carries a message count, the disposition applied (<code>none</code>/<code>quarantine</code>/<code>reject</code>), and the raw SPF/DKIM authentication results.</p>'
            . '<p>Reports contain no message content, subject lines, or recipient addresses — only sender IPs and authentication outcomes. Most reporting IPs are mail servers operated by organizations rather than individuals, though a residual subset (self-hosters, compromised residential hosts) can be personal data; this tool\'s retention and enrichment code treats that distinction deliberately rather than assuming either way.</p>',
        ['RFC 7489 §7'],
    ),
    new HelpArticle(
        'header-from',
        'header_from — the alignment anchor',
        $category,
        'header_from is the domain in the visible "From:" field a recipient actually sees — the one DMARC alignment checks against, not the technical envelope sender.',
        '<p><code>header_from</code> is the domain part of the <code>From:</code> header shown to the recipient in their mail client — what most people think of as "who sent this." DMARC deliberately anchors its alignment check here rather than on the technical envelope sender (SMTP <code>MAIL FROM</code>), because header_from is what actually deceives a recipient in a phishing attempt.</p>'
            . '<p>This tool attributes every report to a domain via <code>policy_published/domain</code> (the domain the DMARC policy was published for) rather than <code>report_metadata</code>, since the latter isn\'t reliably "which domain is this report about."</p>',
        ['RFC 7489 §3.1'],
    ),
];
