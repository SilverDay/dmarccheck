<?php

declare(strict_types=1);

namespace App\Enrichment;

/** The full `ip_enrichment` row (minus the key) produced for one IP (spec §6). */
final readonly class EnrichmentResult
{
    public function __construct(
        public ?string $rdns,
        public ?int $asn,
        public ?string $asnOrg,
        public string $label,
    ) {
    }
}
