<?php

declare(strict_types=1);

namespace App\HealthCheck;

/**
 * The latest health-check run's status tally for one domain — a lighter
 * cross-domain shape than HealthCheckSummary (which carries full item
 * detail for the drill-down). Feeds the overview dashboard's posture-card
 * grade (spec §7.1/§11).
 */
final readonly class HealthCheckLatestRun
{
    /** @param array<string, int> $tally counts keyed by HealthCheckItemResult::* */
    public function __construct(
        public string $runAt,
        public string $trigger,
        public array $tally,
    ) {
    }
}
