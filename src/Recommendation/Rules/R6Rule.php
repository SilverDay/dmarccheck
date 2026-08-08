<?php

declare(strict_types=1);

namespace App\Recommendation\Rules;

use App\Recommendation\AnalysisContext;
use App\Recommendation\RuleFinding;

/**
 * spec §10.3 R6: same shape as R5 but evaluated over the longer sustained
 * window and additionally requiring failures spread across multiple
 * distinct report periods — the "sustained across window" test, as
 * opposed to R5's single-window volume spike. High severity.
 */
final class R6Rule implements Rule
{
    public function __construct(private readonly int $volumeThreshold)
    {
    }

    public function evaluate(AnalysisContext $context): array
    {
        $findings = [];

        foreach ($context->sustainedWindowStats as $stat) {
            if ($stat->isKnown()) {
                continue;
            }

            if ($stat->bothFailedCount > $this->volumeThreshold && $stat->distinctReportDays >= $context->sustainedMinDays) {
                $findings[] = new RuleFinding('R6', 'high', $stat->ip, [
                    'ip'                   => $stat->ip,
                    'failed_count'         => $stat->bothFailedCount,
                    'threshold'            => $this->volumeThreshold,
                    'distinct_report_days' => $stat->distinctReportDays,
                    'sustained_min_days'   => $context->sustainedMinDays,
                ]);
            }
        }

        return $findings;
    }
}
