<?php

declare(strict_types=1);

namespace App\Alerting;

/** One alert condition firing for one domain (spec §8). */
final readonly class AlertFinding
{
    /** @param array<string, mixed> $evidence */
    public function __construct(
        public string $type,
        public string $domain,
        public string $message,
        public array $evidence,
    ) {
    }
}
