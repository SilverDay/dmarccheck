<?php

declare(strict_types=1);

namespace App\Alerting\Checks;

use App\Alerting\AlertContext;
use App\Alerting\AlertFinding;
use App\Recommendation\PolicyLevel;

/**
 * spec §8/§9.5: current_published_policy != approved_baseline_policy —
 * unauthorized/accidental DNS change (tamper/misconfig detector). Same
 * condition as R9, but computed directly against `domains` rather than
 * depending on `bin/analyze.php` having already run, so this script stays
 * standalone-runnable. Only fires once a baseline has actually been
 * approved — "no baseline yet" isn't drift, mirrors R9Rule.
 */
final class PolicyDriftCheck implements AlertCheck
{
    public function evaluate(AlertContext $context): array
    {
        if ($context->currentPublishedPolicy === null || $context->approvedBaselinePolicy === null) {
            return [];
        }

        if (PolicyLevel::normalize($context->currentPublishedPolicy) === PolicyLevel::normalize($context->approvedBaselinePolicy)) {
            return [];
        }

        return [new AlertFinding(
            'policy_drift',
            $context->domain,
            \sprintf(
                'Published DMARC policy for %s ("%s") no longer matches the approved baseline ("%s").',
                $context->domain,
                $context->currentPublishedPolicy,
                $context->approvedBaselinePolicy,
            ),
            [
                'current_published_policy' => $context->currentPublishedPolicy,
                'approved_baseline_policy' => $context->approvedBaselinePolicy,
            ],
        )];
    }
}
