<?php

declare(strict_types=1);

use App\Help\HelpArticle;

$category = 'SPF';

return [
    new HelpArticle(
        'spf-overview',
        'What is SPF?',
        $category,
        'SPF is a DNS TXT record listing which mail servers are allowed to send on behalf of your domain, checked against the envelope sender address.',
        '<p>SPF (Sender Policy Framework, RFC 7208) is a DNS TXT record at your domain\'s root listing the IP addresses/ranges and included third-party services authorized to send mail claiming your domain in the SMTP envelope (<code>MAIL FROM</code>). A receiving server looks up that record and checks whether the connecting IP is on the list.</p>'
            . '<p>SPF alone does not stop spoofing of the visible <a href="/help/article?slug=header-from">From: header</a> a recipient sees — that\'s what DMARC\'s <a href="/help/article?slug=dmarc-alignment">alignment</a> requirement adds on top.</p>',
        ['RFC 7208'],
    ),
    new HelpArticle(
        'spf-result-pass',
        'SPF result: pass',
        $category,
        'The sending IP is explicitly authorized by the domain\'s SPF record.',
        '<p><code>pass</code> means the connecting server\'s IP matched a mechanism in the domain\'s SPF record (an <code>ip4</code>/<code>ip6</code> entry, an <code>a</code>/<code>mx</code> lookup, or an <code>include:</code>). This satisfies SPF for DMARC purposes as long as the authenticated domain also <a href="/help/article?slug=spf-alignment">aligns</a> with header_from.</p>',
        ['RFC 7208 §2.6'],
    ),
    new HelpArticle(
        'spf-result-fail',
        'SPF result: fail',
        $category,
        'The sending IP is explicitly NOT authorized — the record ends in -all (hard fail) and no mechanism matched.',
        '<p><code>fail</code> means the SPF record explicitly denies this sender — it ends in <code>-all</code> (see <a href="/help/article?slug=spf-all-qualifier">the all qualifier</a>) and no earlier mechanism matched the connecting IP. Receivers are expected to treat this as a strong signal, though DMARC (not SPF itself) is what actually decides whether to reject/quarantine the message overall.</p>',
        ['RFC 7208 §2.6'],
    ),
    new HelpArticle(
        'spf-result-softfail',
        'SPF result: softfail (~all)',
        $category,
        'A weak "probably not authorized" signal from a record ending in ~all — receivers are asked to accept but flag the mail, not reject it.',
        '<p><code>softfail</code> comes from an SPF record ending in <code>~all</code>: the sender doesn\'t match any authorized mechanism, but the domain is asking receivers to accept the mail anyway while treating it with suspicion (e.g. extra spam-filter weight), rather than rejecting outright. It\'s a common transitional state while rolling out a new SPF record.</p>',
        ['RFC 7208 §2.6'],
    ),
    new HelpArticle(
        'spf-result-neutral',
        'SPF result: neutral (?all)',
        $category,
        'The domain explicitly declines to make a statement about this sender — equivalent to having no SPF opinion either way.',
        '<p><code>neutral</code> comes from an SPF record ending in <code>?all</code>, or from an explicit <code>?</code>-qualified mechanism matching: the domain owner is deliberately saying "no assertion" about whether this sender is authorized. It carries essentially no weight for spam filtering.</p>',
        ['RFC 7208 §2.6'],
    ),
    new HelpArticle(
        'spf-result-none',
        'SPF result: none',
        $category,
        'No SPF record exists for the domain at all, so no check could be performed.',
        '<p><code>none</code> means the domain in the checked identity has no SPF record published — there was nothing to evaluate against. This is different from a fail: it\'s an absence of policy, not a denial.</p>',
        ['RFC 7208 §2.6'],
    ),
    new HelpArticle(
        'spf-result-temperror',
        'SPF result: temperror',
        $category,
        'A transient DNS error (timeout, SERVFAIL) prevented SPF evaluation from completing — retrying later would likely succeed.',
        '<p><code>temperror</code> means SPF evaluation hit a temporary problem — a DNS timeout or server error — while looking up records, not a problem with the SPF record\'s content itself. It usually resolves on its own; persistent temperror across many reports can indicate a flaky or overloaded DNS provider for the domain.</p>',
        ['RFC 7208 §2.6'],
    ),
    new HelpArticle(
        'spf-result-permerror',
        'SPF result: permerror',
        $category,
        'A permanent problem with the SPF record itself — malformed syntax, or exceeding the 10-DNS-lookup limit — that will not resolve without fixing the record.',
        '<p><code>permerror</code> means the SPF record itself is broken in a way no retry will fix: invalid syntax, or exceeding the <a href="/help/article?slug=spf-lookup-limit">10-DNS-lookup limit</a>. Every evaluator will hit the same error until the record is corrected. This tool\'s R4 recommendation checks the live lookup count specifically to catch the lookup-limit case before receivers start permerroring on your mail.</p>',
        ['RFC 7208 §4.6.4'],
    ),
    new HelpArticle(
        'spf-lookup-limit',
        'The 10-DNS-lookup limit',
        $category,
        'SPF evaluation aborts with permerror once it has performed more than 10 DNS lookups (nested includes, a/mx/ptr/exists mechanisms) resolving one record.',
        '<p>RFC 7208 caps SPF evaluation at 10 DNS-querying mechanisms (<code>include</code>, <code>a</code>, <code>mx</code>, <code>ptr</code>, <code>exists</code> — plain <code>ip4</code>/<code>ip6</code> don\'t count) to bound the work a lookup can force on a resolver. Each nested <code>include:</code> (common with third-party senders like <code>include:_spf.google.com</code>) counts toward the total, so stacking several email providers is the usual way domains exceed it.</p>'
            . '<p>Exceeding the limit is a hard <a href="/help/article?slug=spf-result-permerror">permerror</a> — the fix is consolidating includes (e.g. via a provider-specific "flatten" service) or dropping unused ones, not adding more.</p>',
        ['RFC 7208 §4.6.4'],
    ),
    new HelpArticle(
        'spf-all-qualifier',
        'The all qualifier: -all, ~all, ?all, +all',
        $category,
        'The mechanism at the end of an SPF record deciding what happens when nothing else matched: -all (fail), ~all (softfail), ?all (neutral), +all (pass — effectively no restriction, avoid).',
        '<p>Every SPF record ends with an <code>all</code> mechanism (implicit <code>?all</code> if omitted) that catches any sender not matched by an earlier rule:</p>'
            . '<p><code>-all</code> — hard fail, the domain asserts this list is exhaustive.<br>'
            . '<code>~all</code> — softfail, "probably not us, but don\'t reject."<br>'
            . '<code>?all</code> — neutral, no assertion either way.<br>'
            . '<code>+all</code> — pass, meaning literally any IP is "authorized." This defeats the purpose of SPF entirely and should never appear on a domain that wants any anti-spoofing benefit.</p>',
        ['RFC 7208 §5.1'],
    ),
    new HelpArticle(
        'spf-alignment',
        'SPF alignment: MAIL FROM vs header_from',
        $category,
        'SPF authenticates the envelope MAIL FROM domain, which is often invisible to the recipient — DMARC alignment then checks whether that matches the visible From: domain.',
        '<p>SPF\'s pass/fail decision is about the SMTP envelope sender (<code>MAIL FROM</code>, sometimes called the "bounce address" or <code>Return-Path</code>) — a technical address the recipient usually never sees, and which forwarders/mailing lists commonly rewrite to their own domain. DMARC then separately checks whether that authenticated domain <a href="/help/article?slug=dmarc-alignment">aligns</a> with the visible <a href="/help/article?slug=header-from">header_from</a> domain, per the <a href="/help/article?slug=dmarc-aspf">aspf</a> mode.</p>'
            . '<p>This is exactly why forwarded mail often fails DMARC on the SPF path even when the original sender was legitimate — the forwarder\'s MAIL FROM doesn\'t align with the original header_from. This tool\'s R12 recommendation recognizes that pattern for known forwarders and explicitly advises no action.</p>',
        ['RFC 7208 §2.4'],
    ),
];
