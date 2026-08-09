<?php

declare(strict_types=1);

use App\Help\HelpArticle;

$category = 'Health-check results';

return [
    new HelpArticle(
        'hc-status-pass',
        'Health-check status: pass',
        $category,
        'The check ran successfully and found the expected, healthy configuration.',
        '<p><code>pass</code> means the check completed and everything it looked for was present and correct — e.g. a valid DMARC record was found, or the STARTTLS handshake succeeded with a valid certificate. It says nothing about checks that weren\'t run.</p>',
        [],
    ),
    new HelpArticle(
        'hc-status-warn',
        'Health-check status: warn',
        $category,
        'The check ran successfully but found something suboptimal — not broken, but worth attention.',
        '<p><code>warn</code> means the check completed and found a configuration that works but isn\'t ideal — for example a DMARC record still at <code>p=none</code>, or an SPF record close to the 10-lookup limit. Nothing is actively failing; this is a signal to plan an improvement, not an incident.</p>',
        [],
    ),
    new HelpArticle(
        'hc-status-fail',
        'Health-check status: fail',
        $category,
        'The check ran successfully and confirmed a real problem — a missing record, a broken handshake, an actual blocklist hit.',
        '<p><code>fail</code> means the check completed and definitively found the thing it was looking for to be missing, broken, or actively bad — e.g. no MX record resolves, or the domain is confirmed listed on Spamhaus. This is a confirmed negative result, distinct from <a href="/help/article?slug=hc-status-error">error</a>, which means the check couldn\'t reach a conclusion at all.</p>',
        [],
    ),
    new HelpArticle(
        'hc-status-error',
        'Health-check status: error',
        $category,
        'The check itself couldn\'t complete — a DNS timeout, an unconfigured API key, a network failure. This is unknown, not a pass and not a fail.',
        '<p><code>error</code> is the one status distinction this app treats as a hard requirement (spec §11.3): a check that couldn\'t run to completion — a DNS resolver timeout, a missing Spamhaus DQS API key, a network error mid-lookup — is reported as <code>error</code>, never silently folded into <code>pass</code> or <code>fail</code>. An unresolvable check is not a passing check, and it\'s also not proof of a real problem.</p>'
            . '<p><code>healthGrade()</code>\'s worst-status-wins logic (used for the domain-list posture badges) ranks <code>error</code> above <code>warn</code> specifically so a blind spot never quietly looks healthier than a known, minor issue.</p>',
        [],
    ),
    new HelpArticle(
        'hc-status-info',
        'Health-check status: info',
        $category,
        'Informational only — the check observed something worth noting that isn\'t a pass/warn/fail judgment (e.g. a feature simply isn\'t configured, which may be intentional).',
        '<p><code>info</code> covers observations that don\'t fit a pass/warn/fail judgment — for example, MTA-STS being unconfigured is reported as <code>info</code> rather than <code>fail</code>, since not every domain needs it and its absence isn\'t a security regression the way a missing DMARC record would be.</p>',
        [],
    ),
    new HelpArticle(
        'hc-mx',
        'MX check',
        $category,
        'Confirms the domain has resolvable MX records pointing at reachable mail servers — the basic prerequisite for receiving any mail at all.',
        '<p>Checks that the domain publishes at least one MX record and that it resolves to a real host. This is independent of DMARC entirely — a domain can have perfect DMARC/SPF/DKIM and still be unable to receive mail if MX is broken, or conversely may deliberately have no MX at all if it never receives mail (see <a href="/help/article?slug=non-sending-domain">non-sending domains</a>).</p>',
        [],
    ),
    new HelpArticle(
        'hc-dnssec',
        'DNSSEC check',
        $category,
        'Confirms the domain\'s zone is signed with DNSSEC, which protects DNS answers (including your SPF/DKIM/DMARC records themselves) from being tampered with in transit.',
        '<p>DNSSEC cryptographically signs DNS responses so a resolver can verify they weren\'t forged or altered — including the very SPF/DKIM/DMARC records this tool depends on for authentication decisions. This check specifically queries DS records via <code>dig</code> (native PHP DNS functions can\'t retrieve them), pinned to the resolver configured in <code>healthcheck.resolver</code>.</p>'
            . '<p>Absence of DNSSEC is a posture signal, not an active break — most domains today still don\'t sign their zones, so this is typically reported as <code>info</code>/<code>warn</code> rather than <code>fail</code>.</p>',
        ['RFC 4033'],
    ),
    new HelpArticle(
        'hc-mta-sts',
        'MTA-STS check',
        $category,
        'MTA-STS enforces that inbound mail to your domain is delivered over an encrypted, certificate-validated connection — checked here by looking for the DNS record and fetching the policy file.',
        '<p>MTA-STS (RFC 8461) lets a domain require that other mail servers only deliver to it over TLS with a valid certificate, closing a gap opportunistic STARTTLS leaves open (a downgrade attacker can just strip STARTTLS since it\'s unauthenticated by default). This check looks for the <code>_mta-sts.yourdomain.com</code> DNS TXT record and, if present, fetches the policy file over HTTPS to validate it.</p>'
            . '<p>Its companion, <a href="/help/article?slug=hc-tls-rpt">TLS-RPT</a>, is what tells you whether that enforcement is actually being respected in practice.</p>',
        ['RFC 8461'],
    ),
    new HelpArticle(
        'hc-tls-rpt',
        'TLS-RPT check',
        $category,
        'Confirms the domain publishes a TLS-RPT DNS record requesting reports on transport-security failures — separate from actually ingesting those reports.',
        '<p>TLS-RPT (RFC 8460) is a DNS record at <code>_smtp._tls.yourdomain.com</code> requesting that other mail servers report back when they fail to establish a secure (STARTTLS/MTA-STS) connection to deliver mail to you — visibility into transport-layer failures that DMARC aggregate reports don\'t cover at all. This health check only confirms the DNS record\'s presence; this tool separately <em>ingests</em> the RFC 8460 JSON reports themselves via the same mailbox-polling pipeline used for DMARC XML, stored in dedicated tables since the two report formats don\'t map onto each other cleanly.</p>',
        ['RFC 8460'],
    ),
    new HelpArticle(
        'hc-bimi',
        'BIMI check',
        $category,
        'BIMI lets your brand logo appear next to your mail in supporting email clients — but only once DMARC enforcement is strict enough that the logo claim is trustworthy.',
        '<p>BIMI (Brand Indicators for Message Identification) publishes a DNS record pointing at your logo, which supporting mail clients (e.g. Gmail) display next to authenticated mail from your domain. Providers generally require the domain to already be at DMARC <code>p=quarantine</code> or <code>p=reject</code> before honoring a BIMI record — otherwise anyone could spoof mail claiming your logo. This check is purely informational for most domains that haven\'t opted into BIMI.</p>',
        [],
    ),
    new HelpArticle(
        'hc-starttls',
        'STARTTLS check',
        $category,
        'Performs a real SMTP connection to the domain\'s mail server and confirms it offers STARTTLS with a valid, matching certificate.',
        '<p>Unlike the DNS-only checks, this one opens an actual SMTP connection to the domain\'s MX server, issues <code>STARTTLS</code>, and validates the resulting certificate (hostname match, expiry, chain of trust). This confirms mail delivered <em>to</em> your domain can be encrypted in transit — the receiving-side complement to the sending-side guarantees SPF/DKIM/DMARC provide.</p>',
        [],
    ),
    new HelpArticle(
        'hc-dnsbl',
        'DNSBL (IP blocklist) check',
        $category,
        'Checks whether the domain\'s sending IP(s) are listed on Spamhaus ZEN, an IP-based reputation blocklist many receivers consult before accepting mail.',
        '<p>A DNSBL (DNS-based Blocklist) lists individual IP addresses with a history of sending spam or being compromised. This check queries Spamhaus ZEN via Spamhaus\'s keyed DQS service rather than the free public mirrors, since the public mirrors block queries from non-attributable resolvers — which includes most hosting-provider networks this tool would typically run from.</p>'
            . '<p>A listing here means mail from that IP may be rejected or heavily filtered by many receivers regardless of what SPF/DKIM/DMARC say — it\'s a reputation problem, not an authentication one.</p>',
        [],
    ),
    new HelpArticle(
        'hc-rhsbl',
        'RHSBL (domain blocklist) check',
        $category,
        'Checks whether the domain name itself (not an IP) is listed on Spamhaus DBL, a domain-based reputation blocklist.',
        '<p>An RHSBL (Right-Hand-Side Blocklist) lists domain <em>names</em> rather than IPs — relevant when the domain itself (as it appears in URLs or the From: address) has a bad reputation, independent of which IP is currently sending. This check queries Spamhaus DBL, again via the keyed DQS service for the same non-attributable-resolver reason as the <a href="/help/article?slug=hc-dnsbl">IP blocklist check</a>.</p>',
        [],
    ),
    new HelpArticle(
        'hc-fcrdns',
        'FCrDNS check',
        $category,
        'Confirms the sending IP\'s reverse-DNS hostname resolves forward back to the same IP — a basic legitimacy signal many receivers require before even considering a message.',
        '<p>Forward-confirmed reverse DNS (FCrDNS) checks that the sending IP\'s PTR (reverse DNS) record points to a hostname, and that hostname\'s own A/AAAA record resolves back to the same IP — a two-way match. Many receiving mail servers treat a mismatch or missing PTR record as an automatic red flag, independent of SPF/DKIM/DMARC, since it\'s cheap to fake a From: address but harder to fake a consistent forward/reverse DNS chain.</p>',
        [],
    ),
    new HelpArticle(
        'hc-report-auth',
        'Cross-domain report-destination authorization check',
        $category,
        'When rua= points at a mailbox on a different domain than the one being monitored, that destination domain must explicitly authorize accepting reports for this domain via its own DNS record.',
        '<p>If a domain\'s <a href="/help/article?slug=dmarc-rua">rua=</a> address lives on a different domain (e.g. <code>example.com</code>\'s reports go to a mailbox at <code>reports.example-corp.net</code>), RFC 7489 requires the <em>destination</em> domain to publish an authorization record — <code>example.com._report._dmarc.example-corp.net</code> — proving it consents to receive reports about <code>example.com</code>. Without it, some receivers refuse to send reports there at all.</p>'
            . '<p>This check derives the expected destination dynamically from live DNS (parsing the domain\'s own published <code>rua=</code>) and verifies the record exists. The domain page\'s "Cross-domain report authorization" card separately <em>predicts</em> the exact record text you\'d need — from <code>app.mail_from</code>\'s domain — so you can copy-paste it into DNS before the record (or even the domain\'s own <code>rua=</code>) exists yet.</p>',
        ['RFC 7489 §7.1'],
    ),
];
