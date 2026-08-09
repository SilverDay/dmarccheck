<?php

declare(strict_types=1);

namespace App\Alerting\Checks;

use App\Alerting\AlertContext;
use App\Alerting\AlertFinding;

/**
 * spec §8/§9.5: an unknown-labeled source IP exceeding a volume threshold
 * within the alert window — early warning of a spoofing campaign. Uses the
 * plain `ip_enrichment.label` classification `bin/enrich.php` maintains
 * (not the domain-scoped `KnownSenderMatcher::matchForDomain()` the
 * recommendation engine uses for R5/R6), keeping this a lightweight, fast,
 * independent daily tripwire.
 */
final class UnknownVolumeCheck implements AlertCheck
{
    public function __construct(private readonly int $volumeThreshold)
    {
    }

    public function evaluate(AlertContext $context): array
    {
        $findings = [];

        foreach ($context->unknownIpVolumes as $volume) {
            if ($volume->count <= $this->volumeThreshold) {
                continue;
            }

            $findings[] = new AlertFinding(
                'unknown_volume',
                $context->domain,
                \sprintf(
                    'Unknown-labeled source %s sent %d message(s) reported against %s (threshold: %d).',
                    $volume->ip,
                    $volume->count,
                    $context->domain,
                    $this->volumeThreshold,
                ),
                [
                    'ip'        => $volume->ip,
                    'count'     => $volume->count,
                    'threshold' => $this->volumeThreshold,
                ],
            );
        }

        return $findings;
    }
}
