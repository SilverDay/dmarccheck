<?php

declare(strict_types=1);

use App\Help\HelpArticle;

$category = 'DKIM';

return [
    new HelpArticle(
        'dkim-overview',
        'What is DKIM?',
        $category,
        'DKIM cryptographically signs outgoing mail with a private key; receivers verify the signature against a public key published in DNS, proving the message wasn\'t altered in transit and really came from that domain.',
        '<p>DKIM (DomainKeys Identified Mail, RFC 6376) attaches a <code>DKIM-Signature</code> header to outgoing mail, signed with a private key the sending domain controls. The receiver fetches the matching public key from a DNS TXT record at <code>&lt;<a href="/help/article?slug=dkim-selector">selector</a>&gt;._domainkey.&lt;domain&gt;</code> and verifies the signature, which also covers key headers and (usually) the body — so DKIM additionally proves the message wasn\'t tampered with in transit, unlike SPF.</p>'
            . '<p>Unlike SPF (tied to the sending IP), DKIM signatures survive being relayed through intermediate servers, which is why forwarded mail is more likely to still pass DKIM than SPF.</p>',
        ['RFC 6376'],
    ),
    new HelpArticle(
        'dkim-result-pass',
        'DKIM result: pass',
        $category,
        'The signature verified successfully against the public key published for that selector — the message is intact and really was signed by that domain.',
        '<p><code>pass</code> means the receiver fetched the public key for the signature\'s <code>d=</code>/<code>s=</code> domain and selector, and the cryptographic signature checked out against the message as received. This satisfies DKIM for DMARC purposes as long as the signing domain also <a href="/help/article?slug=dkim-alignment">aligns</a> with header_from.</p>',
        ['RFC 6376 §6.3'],
    ),
    new HelpArticle(
        'dkim-result-fail',
        'DKIM result: fail',
        $category,
        'The signature did not verify — either the message was modified after signing, the wrong key was used, or the DNS key record is missing/wrong.',
        '<p><code>fail</code> covers several distinct underlying problems the aggregate report doesn\'t always distinguish: the message body/headers changed after signing (some mailing lists and forwarders rewrite content, breaking the signature), the selector\'s DNS key record was deleted or rotated, or the signature was simply malformed. A known-good sender with a sudden spike in DKIM fail is worth checking for a recent key rotation or a mail-flow change.</p>',
        ['RFC 6376 §6.3'],
    ),
    new HelpArticle(
        'dkim-selector',
        'What a DKIM selector is',
        $category,
        'The s= tag in a DKIM-Signature header names which key was used — receivers look it up at <selector>._domainkey.<domain> to find the matching public key.',
        '<p>A domain can publish multiple DKIM keys simultaneously (e.g. one per sending platform, or during key rotation), each under its own <strong>selector</strong> — an arbitrary label chosen by whoever configured signing (common examples: <code>google</code>, <code>selector1</code>, <code>k1</code>). The signature header\'s <code>s=</code> tag names which one to check, and the receiver looks up <code>&lt;selector&gt;._domainkey.yourdomain.com</code> as a TXT record to get that key.</p>'
            . '<p>This tool\'s DKIM-selector health check merges selectors from config with ones already observed in that domain\'s actual reports, since there\'s no way to enumerate every valid selector from DNS alone — see <a href="/help/article?slug=dkim-not-enumerable">why full coverage can\'t be guaranteed</a>.</p>',
        ['RFC 6376 §3.1'],
    ),
    new HelpArticle(
        'dkim-alignment',
        'DKIM alignment: signing domain vs header_from',
        $category,
        'DKIM authenticates whichever domain is in the signature\'s d= tag — DMARC alignment then checks whether that matches the visible From: domain.',
        '<p>The domain DKIM actually authenticates is the signature\'s <code>d=</code> tag, which is chosen by whoever configured signing and is not required to match anything else in the message. DMARC then checks whether <code>d=</code> <a href="/help/article?slug=dmarc-alignment">aligns</a> with <a href="/help/article?slug=header-from">header_from</a>, per the <a href="/help/article?slug=dmarc-adkim">adkim</a> mode. A message can be legitimately signed by a third-party sending platform (<code>d=platform.example</code>) while claiming <code>From: you@yourdomain.com</code> — DKIM passes, but alignment fails, unless that platform signs with your domain instead.</p>',
        ['RFC 6376 §3.5'],
    ),
    new HelpArticle(
        'dkim-not-enumerable',
        'Why the health check can\'t guarantee full DKIM coverage',
        $category,
        'DNS has no way to list every DKIM selector a domain has ever used, so a health-check probe can only confirm the selectors it already knows about, never certify "DKIM is fully configured."',
        '<p>Unlike an MX or SPF record, there is no DNS mechanism to ask "what DKIM selectors does this domain use?" — a selector only becomes discoverable once you\'ve seen it in a signed message or been told about it directly. This tool\'s DKIM-selector health check therefore probes the union of <code>healthcheck.dkim_selectors</code> (configured) and selectors already observed in that domain\'s ingested reports — a growing but never provably complete list.</p>'
            . '<p>A <code>fail</code> or missing result here means a specific known selector has a problem, not that DKIM is broken domain-wide; a clean result means "every selector we know about checks out," not "DKIM is fully configured."</p>',
        [],
    ),
];
