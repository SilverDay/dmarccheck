<?php

declare(strict_types=1);

namespace App\HealthCheck\Checks;

use App\HealthCheck\DnsResolver;
use App\HealthCheck\HealthCheckItemResult;

/** Optional/informational per spec §11.2. Only probes the common "default" selector. */
final class BimiCheck implements HealthCheck
{
    public function __construct(private readonly DnsResolver $dns)
    {
    }

    public function run(string $domain): array
    {
        $txt     = $this->dns->txt('default._bimi.' . $domain);
        $records = array_values(array_filter(
            $txt,
            static fn (string $t): bool => str_starts_with(strtolower(trim($t)), 'v=bimi1')
        ));

        return [new HealthCheckItemResult(
            'dns',
            'bimi',
            $records !== [] ? HealthCheckItemResult::PASS : HealthCheckItemResult::INFO,
            [
                'reason' => $records !== [] ? 'BIMI record present at default selector' : 'no BIMI record at default selector (optional)',
                ...($records !== [] ? ['record' => $records[0]] : []),
            ]
        )];
    }
}
