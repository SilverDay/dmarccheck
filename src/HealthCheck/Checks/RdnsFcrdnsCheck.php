<?php

declare(strict_types=1);

namespace App\HealthCheck\Checks;

use App\Enrichment\RdnsResolver;
use App\HealthCheck\DnsResolver;
use App\HealthCheck\HealthCheckItemResult;

/**
 * spec §11.2: sending IPs should have a PTR that resolves forward-
 * confirmed (FCrDNS) — a common deliverability/reputation factor, not a
 * hard requirement, so a missing/non-confirming PTR is `warn`, not `fail`.
 * Reuses App\Enrichment\RdnsResolver as-is rather than a second rDNS
 * wrapper — same interface, same gethostbyaddr()-based implementation.
 */
final class RdnsFcrdnsCheck implements HealthCheck
{
    public function __construct(
        private readonly DnsResolver $dns,
        private readonly RdnsResolver $rdns,
    ) {
    }

    public function run(string $domain): array
    {
        $mxRecords = $this->dns->mx($domain);

        if ($mxRecords === []) {
            return [new HealthCheckItemResult('reputation', 'fcrdns', HealthCheckItemResult::ERROR, [
                'reason' => 'no MX records to test',
            ])];
        }

        $results = [];

        foreach ($mxRecords as $mx) {
            $ips = array_merge($this->dns->a($mx->host), $this->dns->aaaa($mx->host));

            foreach ($ips as $ip) {
                $results[] = $this->checkIp($mx->host, $ip);
            }
        }

        return $results;
    }

    private function checkIp(string $mxHost, string $ip): HealthCheckItemResult
    {
        $ptr = $this->rdns->resolve($ip);

        if ($ptr === null) {
            return new HealthCheckItemResult('reputation', 'fcrdns', HealthCheckItemResult::WARN, [
                'ip'      => $ip,
                'mx_host' => $mxHost,
                'reason'  => 'no PTR record',
            ]);
        }

        $forward   = array_merge($this->dns->a($ptr), $this->dns->aaaa($ptr));
        $confirmed = \in_array($ip, $forward, true);

        return new HealthCheckItemResult(
            'reputation',
            'fcrdns',
            $confirmed ? HealthCheckItemResult::PASS : HealthCheckItemResult::WARN,
            [
                'ip'      => $ip,
                'mx_host' => $mxHost,
                'ptr'     => $ptr,
                'reason'  => $confirmed ? 'forward-confirmed' : 'PTR does not forward-resolve back to this IP',
            ]
        );
    }
}
