<?php

declare(strict_types=1);

namespace App\Recommendation\Rules;

use App\Recommendation\AnalysisContext;
use App\Recommendation\RuleFinding;

/**
 * spec §10.3 R1: known sender, SPF fails cleanly (not an alignment issue —
 * see R3), DKIM passes. Low severity, routine auth hygiene. Excludes
 * known-forwarder-labeled senders — same SPF-fail/DKIM-pass shape, but
 * routed to R12 instead (adding a forwarder to SPF is usually wrong/
 * impossible for shared infrastructure you don't control).
 */
final class R1Rule implements Rule
{
    public function evaluate(AnalysisContext $context): array
    {
        $findings = [];

        foreach ($context->standardWindowStats as $stat) {
            if (!$stat->isKnown() || $stat->isKnownForwarder()) {
                continue;
            }

            if ($stat->spfOnlyFailCount > 0 && !$stat->spfAlignmentIssue) {
                $findings[] = new RuleFinding('R1', 'low', $stat->ip, [
                    'ip'             => $stat->ip,
                    'known_label'    => $stat->knownLabel,
                    'spf_fail_count' => $stat->spfOnlyFailCount,
                    'window_days'    => $context->windowDays,
                ]);
            }
        }

        return $findings;
    }
}
