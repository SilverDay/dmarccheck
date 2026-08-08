<?php

declare(strict_types=1);

namespace App\Enrichment;

interface AsnLookup
{
    public function lookup(string $ip): ?AsnInfo;
}
