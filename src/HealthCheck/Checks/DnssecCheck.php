<?php

declare(strict_types=1);

namespace App\HealthCheck\Checks;

use App\HealthCheck\DigLookup;
use App\HealthCheck\HealthCheckItemResult;

/** Informational per spec §11.2 — absence isn't a mail failure, just a posture signal. */
final class DnssecCheck implements HealthCheck
{
    public function __construct(private readonly DigLookup $dig)
    {
    }

    public function run(string $domain): array
    {
        $answer = $this->dig->query($domain, 'DS');

        if ($answer === null) {
            return [new HealthCheckItemResult('dns', 'dnssec', HealthCheckItemResult::ERROR, [
                'reason' => 'DS lookup failed or timed out',
            ])];
        }

        if ($answer === []) {
            return [new HealthCheckItemResult('dns', 'dnssec', HealthCheckItemResult::INFO, [
                'reason' => 'zone is not DNSSEC-signed (informational, not a mail failure)',
            ])];
        }

        return [new HealthCheckItemResult('dns', 'dnssec', HealthCheckItemResult::PASS, [
            'ds_records' => $answer,
        ])];
    }
}
