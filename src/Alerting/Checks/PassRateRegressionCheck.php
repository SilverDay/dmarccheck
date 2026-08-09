<?php

declare(strict_types=1);

namespace App\Alerting\Checks;

use App\Alerting\AlertContext;
use App\Alerting\AlertFinding;

/**
 * spec §8/§9.5: overall DMARC pass rate for a domain drops below a
 * threshold vs. its trailing average — flags either a broken legitimate
 * sender (a shipped config change) or an abuse spike. Skips (no finding)
 * unless both windows meet the minimum sample size, to avoid noise on tiny
 * samples or a domain with no baseline history yet.
 */
final class PassRateRegressionCheck implements AlertCheck
{
    public function __construct(
        private readonly float $dropPctThreshold,
        private readonly int $minSampleCount,
    ) {
    }

    public function evaluate(AlertContext $context): array
    {
        if ($context->recentTotalCount < $this->minSampleCount || $context->baselineTotalCount < $this->minSampleCount) {
            return [];
        }

        if ($context->recentPassRatePct === null || $context->baselinePassRatePct === null) {
            return [];
        }

        $drop = $context->baselinePassRatePct - $context->recentPassRatePct;

        if ($drop <= $this->dropPctThreshold) {
            return [];
        }

        return [new AlertFinding(
            'pass_rate_regression',
            $context->domain,
            \sprintf(
                'DMARC pass rate for %s dropped to %.1f%% (from a %.1f%% trailing average, a %.1f point drop).',
                $context->domain,
                $context->recentPassRatePct,
                $context->baselinePassRatePct,
                $drop,
            ),
            [
                'recent_pass_rate_pct'   => $context->recentPassRatePct,
                'baseline_pass_rate_pct' => $context->baselinePassRatePct,
                'drop_pct'               => $drop,
                'threshold_pct'          => $this->dropPctThreshold,
                'recent_total_count'     => $context->recentTotalCount,
                'baseline_total_count'   => $context->baselineTotalCount,
            ],
        )];
    }
}
