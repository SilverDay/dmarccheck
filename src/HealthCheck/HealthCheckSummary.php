<?php

declare(strict_types=1);

namespace App\HealthCheck;

/** The latest `health_checks` run for a domain, with its items, for the dashboard drill-down (spec §7.2). */
final readonly class HealthCheckSummary
{
    /** @param list<HealthCheckItemResult> $items */
    public function __construct(
        public string $runAt,
        public string $trigger,
        public array $items,
    ) {
    }
}
