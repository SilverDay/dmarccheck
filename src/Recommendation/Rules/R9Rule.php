<?php

declare(strict_types=1);

namespace App\Recommendation\Rules;

use App\Recommendation\AnalysisContext;
use App\Recommendation\PolicyLevel;
use App\Recommendation\RuleFinding;

/**
 * spec §10.3 R9: current_published_policy != approved_baseline_policy —
 * DNS drift/tamper. Only fires once a baseline has actually been approved
 * (spec §10.6: seeding must be an explicit admin action, never silent) —
 * "no baseline yet" is a different, unaddressed state, not drift, so this
 * stays silent rather than inventing a rule outside the R1-R12 catalog.
 * High severity — eligible for alerting (§8).
 */
final class R9Rule implements Rule
{
    public function evaluate(AnalysisContext $context): array
    {
        if ($context->approvedBaselinePolicy === null || $context->currentPublishedPolicy === null) {
            return [];
        }

        if (PolicyLevel::normalize($context->currentPublishedPolicy) === PolicyLevel::normalize($context->approvedBaselinePolicy)) {
            return [];
        }

        return [new RuleFinding('R9', 'high', null, [
            'current_published_policy' => $context->currentPublishedPolicy,
            'approved_baseline_policy' => $context->approvedBaselinePolicy,
        ])];
    }
}
