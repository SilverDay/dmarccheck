<?php

declare(strict_types=1);

namespace App\Alerting;

/** Per-source-IP message volume from an `unknown`-labeled sender within the alert window (spec §8). */
final readonly class UnknownIpVolume
{
    public function __construct(
        public string $ip,
        public int $count,
    ) {
    }
}
