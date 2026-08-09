<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Http\View;

/**
 * Public landing page (docs/feature-landing-page.md) — orientation for a
 * first-time invitee before they hit the bare login form, not a marketing
 * site. No database queries, no session-aware content: public/index.php's
 * "/" route dispatches here only when there's no active session at all
 * (see the closure there), so this class never needs to check auth itself.
 */
final class LandingController
{
    public function show(): void
    {
        $body = $this->renderHero()
            . $this->renderAbout()
            . $this->renderCapabilities()
            . $this->renderHelpCta();

        View::render('Welcome', $body, null);
    }

    private function renderHero(): string
    {
        return '<div class="landing-hero">'
            . '<h1>' . View::icon('shield') . ' DMARC Analyzer</h1>'
            . '<p class="lead">Monitor email authentication, catch spoofing, and advance your domains safely toward enforcement — all from one self-hosted dashboard.</p>'
            . '<div class="landing-cta">'
            . '<a href="/login" class="btn btn-primary">Sign in &rarr;</a>'
            . '<a href="/help" class="btn btn-secondary">Read the DMARC 101 guide &rarr;</a>'
            . '</div></div>';
    }

    private function renderAbout(): string
    {
        return '<div class="landing-about">'
            . '<p>This tool ingests DMARC aggregate reports from your mailbox, parses them, enriches source IPs, and surfaces pass/fail trends, unknown senders, and concrete recommendations per domain.</p>'
            . '<p>DMARC aggregate reports are the authoritative evidence base for understanding who is sending as your domain and whether authentication is working. This tool makes that data actionable without requiring manual XML parsing or a third-party SaaS.</p>'
            . '<p>It\'s built for operators running a handful of domains on their own infrastructure, who want visibility and a safe path toward <code>p=reject</code> without handing report data to an external service.</p>'
            . '</div>';
    }

    private function renderCapabilities(): string
    {
        $cards = [
            ['Ingestion', 'Polls your DMARC mailbox automatically; tolerates vendor XML deviations and hostile input.'],
            ['Enrichment', 'Labels source IPs as known infrastructure or unknown senders via rDNS, ASN, and your allowlist.'],
            ['Recommendations', 'R1-R12 rule engine turns report data into prioritized, evidence-backed action items.'],
            ['Health checks', 'Probes SPF, DKIM, DMARC, MX, DNSSEC, MTA-STS, TLS-RPT, blocklists, and more on demand.'],
            ['Alerting', 'Daily digest flags heartbeat failures, policy drift, unknown-sender spikes, and pass-rate drops.'],
            ['DMARC 101', 'Built-in contextual help explains every term, finding, and recommendation — no external reference needed.'],
        ];

        $items = '';

        foreach ($cards as [$title, $description]) {
            $items .= '<div class="card"><h3>' . View::e($title) . '</h3><p class="card-sub">' . View::e($description) . '</p></div>';
        }

        return '<div class="landing-capabilities">' . $items . '</div>';
    }

    private function renderHelpCta(): string
    {
        return '<div class="card landing-help-cta">'
            . '<h2>New to DMARC?</h2>'
            . '<p class="card-sub">The built-in DMARC 101 guide covers everything from SPF basics to reading aggregate reports and understanding each recommendation rule. No account required.</p>'
            . '<a href="/help" class="btn btn-secondary">Browse the help articles &rarr;</a>'
            . '</div>';
    }
}
