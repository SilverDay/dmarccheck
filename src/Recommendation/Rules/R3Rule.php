<?php

declare(strict_types=1);

namespace App\Recommendation\Rules;

use App\Recommendation\AnalysisContext;
use App\Recommendation\RuleFinding;

/**
 * spec §10.3 R3: known sender, auth passes but alignment fails — the raw
 * mechanism (auth_results, pre-alignment) actually passed for at least one
 * failing record. Distinct from R1/R2's genuine auth failure.
 */
final class R3Rule implements Rule
{
    public function evaluate(AnalysisContext $context): array
    {
        $findings = [];

        foreach ($context->standardWindowStats as $stat) {
            if (!$stat->isKnown()) {
                continue;
            }

            $misaligned = [];

            if ($stat->spfAlignmentIssue) {
                $misaligned[] = 'spf';
            }

            if ($stat->dkimAlignmentIssue) {
                $misaligned[] = 'dkim';
            }

            if ($misaligned !== []) {
                $findings[] = new RuleFinding('R3', 'low', $stat->ip, [
                    'ip'                    => $stat->ip,
                    'known_label'           => $stat->knownLabel,
                    'misaligned_mechanisms' => $misaligned,
                    'window_days'           => $context->windowDays,
                ]);
            }
        }

        return $findings;
    }
}
