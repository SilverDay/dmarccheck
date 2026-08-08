<?php

declare(strict_types=1);

namespace App\Recommendation\Rules;

use App\Recommendation\AnalysisContext;
use App\Recommendation\RuleFinding;

/** spec §10.3 R2: known sender, DKIM fails cleanly, SPF passes. Low severity. */
final class R2Rule implements Rule
{
    public function evaluate(AnalysisContext $context): array
    {
        $findings = [];

        foreach ($context->standardWindowStats as $stat) {
            if (!$stat->isKnown() || $stat->isKnownForwarder()) {
                continue;
            }

            if ($stat->dkimOnlyFailCount > 0 && !$stat->dkimAlignmentIssue) {
                $findings[] = new RuleFinding('R2', 'low', $stat->ip, [
                    'ip'              => $stat->ip,
                    'known_label'     => $stat->knownLabel,
                    'dkim_fail_count' => $stat->dkimOnlyFailCount,
                    'window_days'     => $context->windowDays,
                ]);
            }
        }

        return $findings;
    }
}
