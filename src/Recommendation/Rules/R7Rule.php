<?php

declare(strict_types=1);

namespace App\Recommendation\Rules;

use App\Recommendation\AnalysisContext;
use App\Recommendation\PolicyLevel;
use App\Recommendation\RuleFinding;
use App\Recommendation\SourceStat;

/**
 * spec §10.3 R7: at `p=none` with every known sender passing for the full
 * window, and target_policy calls for stricter — safe to advance.
 * Known-sender failures block this (would actually break something);
 * unknown-source failures don't (that's exactly what tightening should
 * catch, not "fallout"). Medium severity.
 */
final class R7Rule implements Rule
{
    public function evaluate(AnalysisContext $context): array
    {
        $current = PolicyLevel::extract($context->currentPublishedPolicy);
        $target  = PolicyLevel::extract($context->targetPolicy);

        if ($current !== 'none' || $target === null || !PolicyLevel::isStricter($target, 'none')) {
            return [];
        }

        if (SourceStat::anyKnownTotalFailure($context->standardWindowStats)) {
            return [];
        }

        return [new RuleFinding('R7', 'medium', null, [
            'current_policy' => $context->currentPublishedPolicy,
            'target_policy'  => $context->targetPolicy,
            'window_days'    => $context->windowDays,
        ])];
    }
}
