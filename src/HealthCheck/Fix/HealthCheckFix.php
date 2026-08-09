<?php

declare(strict_types=1);

namespace App\HealthCheck\Fix;

/**
 * One copy-pasteable DNS record suggested as a mechanical fix for a health
 * check finding — generation only, never applied to any nameserver (this
 * app holds no such credentials and no DNS provider has a universal API).
 */
final readonly class HealthCheckFix
{
    public function __construct(
        public string $label,
        public string $recordName,
        public string $recordType,
        public string $recordValue,
        public string $note,
    ) {
    }
}
