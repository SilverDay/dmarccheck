<?php

declare(strict_types=1);

namespace App\HealthCheck\Checks;

use App\HealthCheck\DnsResolver;
use App\HealthCheck\HealthCheckItemResult;

/** Informational per spec §11.2 — ties into the phase-2 TLS-RPT ingestion, presence-only for now. */
final class TlsRptCheck implements HealthCheck
{
    public function __construct(private readonly DnsResolver $dns)
    {
    }

    public function run(string $domain): array
    {
        $txt     = $this->dns->txt('_smtp._tls.' . $domain);
        $records = array_values(array_filter(
            $txt,
            static fn (string $t): bool => str_starts_with(strtolower(trim($t)), 'v=tlsrptv1')
        ));

        return [new HealthCheckItemResult(
            'dns',
            'tls_rpt',
            $records !== [] ? HealthCheckItemResult::PASS : HealthCheckItemResult::INFO,
            ['reason' => $records !== [] ? 'TLS-RPT record present' : 'no TLS-RPT record published']
        )];
    }
}
