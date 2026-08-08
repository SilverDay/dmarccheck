<?php

declare(strict_types=1);

namespace App\Enrichment;

/**
 * Orchestrates one IP's enrichment (spec §6): rDNS + ASN lookup always run
 * (they're stored regardless of classification), and the label is decided
 * by precedence — known_senders CIDR match, then ASN heuristic, then
 * 'unknown'. No PDO dependency, so this is fully unit-testable with fake
 * RdnsResolver/AsnLookup implementations.
 */
final class EnrichmentService
{
    public function __construct(
        private readonly RdnsResolver $rdnsResolver,
        private readonly AsnLookup $asnLookup,
        private readonly KnownSenderMatcher $knownSenders,
        private readonly EspHeuristic $espHeuristic,
    ) {
    }

    public function enrich(string $ip): EnrichmentResult
    {
        $rdns    = $this->rdnsResolver->resolve($ip);
        $asnInfo = $this->asnLookup->lookup($ip);

        $label = $this->knownSenders->match($ip)
            ?? $this->espHeuristic->classify($asnInfo?->asn)
            ?? 'unknown';

        return new EnrichmentResult($rdns, $asnInfo?->asn, $asnInfo?->org, $label);
    }
}
