<?php

declare(strict_types=1);

namespace App\Recommendation\Rules;

use App\Recommendation\AnalysisContext;
use App\Recommendation\RuleFinding;

/** spec §10.3 R10: domain flagged non-sending but records observed. Medium severity. */
final class R10Rule implements Rule
{
    public function evaluate(AnalysisContext $context): array
    {
        if (!$context->nonSending) {
            return [];
        }

        $total = 0;

        foreach ($context->standardWindowStats as $stat) {
            $total += $stat->totalCount;
        }

        if ($total === 0) {
            return [];
        }

        return [new RuleFinding('R10', 'medium', null, [
            'total_records_observed' => $total,
            'distinct_sources'       => \count($context->standardWindowStats),
            'window_days'            => $context->windowDays,
        ])];
    }
}
