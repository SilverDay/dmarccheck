<?php

declare(strict_types=1);

namespace App\Enrichment;

final readonly class AsnInfo
{
    public function __construct(
        public int $asn,
        public string $org,
    ) {
    }
}
