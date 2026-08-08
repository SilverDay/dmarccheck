<?php

declare(strict_types=1);

namespace App\Enrichment;

/** Used when the GeoLite2 .mmdb file isn't present — degrades, doesn't crash. */
final class NullAsnLookup implements AsnLookup
{
    public function lookup(string $ip): ?AsnInfo
    {
        return null;
    }
}
