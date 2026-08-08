<?php

declare(strict_types=1);

namespace App\HealthCheck\Checks;

use App\HealthCheck\DnsResolver;
use App\HealthCheck\HealthCheckItemResult;
use App\HealthCheck\MxRecord;

final class MxCheck implements HealthCheck
{
    public function __construct(private readonly DnsResolver $dns)
    {
    }

    public function run(string $domain): array
    {
        $records = $this->dns->mx($domain);

        if ($records === []) {
            return [new HealthCheckItemResult('dns', 'mx', HealthCheckItemResult::FAIL, [
                'reason' => 'no MX records found',
            ])];
        }

        $results = [new HealthCheckItemResult('dns', 'mx', HealthCheckItemResult::PASS, [
            'hosts' => array_map(
                static fn (MxRecord $r): array => ['preference' => $r->preference, 'host' => $r->host],
                $records
            ),
        ])];

        foreach ($records as $mx) {
            $a    = $this->dns->a($mx->host);
            $aaaa = $this->dns->aaaa($mx->host);

            $results[] = new HealthCheckItemResult(
                'dns',
                'mx_resolution',
                $a !== [] || $aaaa !== [] ? HealthCheckItemResult::PASS : HealthCheckItemResult::FAIL,
                ['host' => $mx->host, 'preference' => $mx->preference, 'a' => $a, 'aaaa' => $aaaa]
            );
        }

        return $results;
    }
}
