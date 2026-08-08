<?php

declare(strict_types=1);

namespace App\HealthCheck;

final readonly class MxRecord
{
    public function __construct(
        public int $preference,
        public string $host,
    ) {
    }
}
