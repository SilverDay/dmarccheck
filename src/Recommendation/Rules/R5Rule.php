<?php

declare(strict_types=1);

namespace App\Recommendation\Rules;

use App\Recommendation\AnalysisContext;
use App\Recommendation\RuleFinding;

/**
 * spec §10.3 R5: unknown source, total DMARC failure, volume over
 * threshold in the standard window. High severity — "investigate," never
 * "block" (spec §9.4/§10.1: rua data alone never justifies an inbound
 * block; that requires also being observed on the local MX).
 */
final class R5Rule implements Rule
{
    public function __construct(private readonly int $volumeThreshold)
    {
    }

    public function evaluate(AnalysisContext $context): array
    {
        $findings = [];

        foreach ($context->standardWindowStats as $stat) {
            if ($stat->isKnown()) {
                continue;
            }

            if ($stat->bothFailedCount > $this->volumeThreshold) {
                $findings[] = new RuleFinding('R5', 'high', $stat->ip, [
                    'ip'           => $stat->ip,
                    'failed_count' => $stat->bothFailedCount,
                    'threshold'    => $this->volumeThreshold,
                    'window_days'  => $context->windowDays,
                ]);
            }
        }

        return $findings;
    }
}
