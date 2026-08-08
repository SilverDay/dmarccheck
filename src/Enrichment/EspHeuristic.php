<?php

declare(strict_types=1);

namespace App\Enrichment;

/** ASN-based heuristic labelling (spec §6, second/fallback tier). */
final class EspHeuristic
{
    /** @param array<int, string> $knownAsns config's enrichment.known_esp_asns */
    public function __construct(private readonly array $knownAsns)
    {
    }

    public function classify(?int $asn): ?string
    {
        if ($asn === null) {
            return null;
        }

        return $this->knownAsns[$asn] ?? null;
    }
}
