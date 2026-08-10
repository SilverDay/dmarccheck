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
 * classic DMARC (RFC 7489) the staged step was bumping `pct=` toward 100;
 * RFC 9989 (DMARCbis) removed `pct=` as a defined tag, so its replacement
 * for a reversible/staged step is `t=y` (test mode) — binary, not
 * percentage-based (docs/feature-dmarcbis.md D2). Firing logic here is
 * unchanged either way — this rule only compares `current_published_policy`
 * against `target_policy`, regime-agnostic. The exact next step is still
 * left to the human per §10.7 — this tool doesn't compute a staged
 * rollout schedule. Medium severity.
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
