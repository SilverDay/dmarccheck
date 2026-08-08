<?php

declare(strict_types=1);

namespace App\Recommendation\Rules;

use App\Recommendation\AnalysisContext;
use App\Recommendation\RuleFinding;

/**
 * spec §10.3 R12: forwarding-pattern failures from a known forwarder
 * (SPF fails, DKIM survives — the classic forwarding signature). Purely
 * informational — explicitly does not suggest weakening policy or adding
 * the forwarder to SPF, which is usually wrong/impossible for shared
 * forwarding infrastructure you don't control.
 */
final class R12Rule implements Rule
{
    public function evaluate(AnalysisContext $context): array
    {
        $findings = [];

        foreach ($context->standardWindowStats as $stat) {
            if (!$stat->isKnownForwarder() || $stat->spfOnlyFailCount === 0) {
                continue;
            }

            $findings[] = new RuleFinding('R12', 'info', $stat->ip, [
                'ip'             => $stat->ip,
                'known_label'    => $stat->knownLabel,
                'spf_fail_count' => $stat->spfOnlyFailCount,
                'window_days'    => $context->windowDays,
                'note'           => 'Expected forwarding-pattern failure — do not weaken policy or add this forwarder to SPF to "fix" it.',
            ]);
        }

        return $findings;
    }
}
