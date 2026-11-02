<?php

declare(strict_types=1);

namespace App\Recommendation\Rules;

use App\Recommendation\AnalysisContext;
use App\Recommendation\PolicyLevel;
use App\Recommendation\RuleFinding;
use App\Recommendation\SourceStat;

/**
 * spec §10.3 R8: at `p=quarantine` with no known-sender fallout and
 * target_policy calls for stricter still — advance toward `reject`. Under
 * Under classic DMARC, operators could stage enforcement with `pct=`;
 * RFC 9989 removes that tag. Its `t=y` test mode is not a percentage
 * replacement: it requests one-level-lower handling for failing messages.
 * This rule only compares `current_published_policy` against `target_policy`
 * and leaves the exact next step to the human per §10.7. Medium severity.
 */
final class R8Rule implements Rule
{
    public function evaluate(AnalysisContext $context): array
    {
        $current = PolicyLevel::extract($context->currentPublishedPolicy);
        $target  = PolicyLevel::extract($context->targetPolicy);

        if ($current !== 'quarantine' || $target === null || !PolicyLevel::isStricter($target, 'quarantine')) {
            return [];
        }

        if (SourceStat::anyKnownTotalFailure($context->standardWindowStats)) {
            return [];
        }

        return [new RuleFinding('R8', 'medium', null, [
            'current_policy' => $context->currentPublishedPolicy,
            'target_policy'  => $context->targetPolicy,
            'window_days'    => $context->windowDays,
        ])];
    }
}
