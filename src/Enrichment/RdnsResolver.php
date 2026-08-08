<?php

declare(strict_types=1);

namespace App\Enrichment;

/** Exists so EnrichmentService is unit-testable without a real DNS lookup. */
interface RdnsResolver
{
    /** @return string|null the PTR hostname, or null if none resolves */
    public function resolve(string $ip): ?string;
}
