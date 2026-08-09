<?php

declare(strict_types=1);

namespace App\HealthCheck\Checks;

use App\HealthCheck\DigLookup;
use App\HealthCheck\DnsResolver;
use App\HealthCheck\HealthCheckItemResult;

/**
 * spec §11.2/§11.6: IP-based DNSBL (the domain's MX IPs) + domain-based
 * RHSBL/DBL (the domain itself) via Spamhaus DQS. An unconfigured key
 * reports `error` on every item — never silently skipped, never reported
 * as clean — per §11.6's explicit requirement that a blocked/misconfigured
 * query must never be misread as "not listed."
 *
 * The DQS keyed-zone hostname format (config('healthcheck.dnsbl_zones'))
 * was verified live 2026-08-09 against a real DQS key: Spamhaus's "always
 * listed" test entries (ZEN's 127.0.0.2, DBL's dbltest.com) resolve
 * correctly through zen.dq.spamhaus.net/dbl.dq.spamhaus.net (note "dq",
 * not "dqs" — an earlier guess), and a genuinely clean domain correctly
 * comes back empty. The free public mirrors (zen.spamhaus.org) are gone
 * too — confirmed NXDOMAIN with a real authoritative SOA, not a blocked
 * query — so DQS is the only path now, not just the recommended one.
 */
final class DnsblCheck implements HealthCheck
{
    /** Spamhaus's documented error/blocked-query sentinel — never a real "listed" answer. */
    private const array ERROR_SENTINELS = ['127.255.255.254', '127.255.255.255'];

    /** @param array<string, string> $zones zone label => DQS zone hostname, e.g. 'zen' => 'zen.dqs.spamhaus.net' */
    public function __construct(
        private readonly DnsResolver $dns,
        private readonly DigLookup $dig,
        private readonly string $dqsKey,
        private readonly array $zones,
    ) {
    }

    public function run(string $domain): array
    {
        if (trim($this->dqsKey) === '') {
            return array_map(
                static fn (string $label): HealthCheckItemResult => new HealthCheckItemResult(
                    'reputation',
                    "dnsbl_$label",
                    HealthCheckItemResult::ERROR,
                    ['reason' => 'Spamhaus DQS key not configured — query not attempted']
                ),
                array_keys($this->zones)
            );
        }

        $results = [];

        foreach ($this->zones as $label => $zoneHost) {
            $results[] = $this->queryDomain($domain, $label, $zoneHost);
        }

        $ips = [];

        foreach ($this->dns->mx($domain) as $mx) {
            $ips = array_merge($ips, $this->dns->a($mx->host));
        }

        foreach (array_unique($ips) as $ip) {
            foreach ($this->zones as $label => $zoneHost) {
                $results[] = $this->queryIp($ip, $label, $zoneHost);
            }
        }

        return $results;
    }

    private function queryDomain(string $domain, string $label, string $zoneHost): HealthCheckItemResult
    {
        $name = $domain . '.' . $this->keyedZone($zoneHost);

        return $this->interpret($this->dig->query($name, 'A'), "dnsbl_$label", ['domain' => $domain, 'zone' => $label]);
    }

    private function queryIp(string $ip, string $label, string $zoneHost): HealthCheckItemResult
    {
        $reversed = $this->reverseIpv4($ip);

        if ($reversed === null) {
            return new HealthCheckItemResult('reputation', "dnsbl_$label", HealthCheckItemResult::ERROR, [
                'ip'     => $ip,
                'reason' => 'IPv6 not supported by this check (DQS IPv6 zones use a different query format)',
            ]);
        }

        $name = $reversed . '.' . $this->keyedZone($zoneHost);

        return $this->interpret($this->dig->query($name, 'A'), "dnsbl_$label", ['ip' => $ip, 'zone' => $label]);
    }

    /**
     * @param list<string>|null $answer
     * @param array<string, string> $context
     */
    private function interpret(?array $answer, string $checkName, array $context): HealthCheckItemResult
    {
        if ($answer === null) {
            return new HealthCheckItemResult('reputation', $checkName, HealthCheckItemResult::ERROR, [
                ...$context,
                'reason' => 'query failed or timed out',
            ]);
        }

        if (array_intersect($answer, self::ERROR_SENTINELS) !== []) {
            return new HealthCheckItemResult('reputation', $checkName, HealthCheckItemResult::ERROR, [
                ...$context,
                'reason' => 'Spamhaus returned a blocked-query/error sentinel, not a real answer',
                'answer' => $answer,
            ]);
        }

        if ($answer === []) {
            return new HealthCheckItemResult('reputation', $checkName, HealthCheckItemResult::PASS, [
                ...$context,
                'reason' => 'not listed',
            ]);
        }

        return new HealthCheckItemResult('reputation', $checkName, HealthCheckItemResult::FAIL, [
            ...$context,
            'reason' => 'listed',
            'answer' => $answer,
        ]);
    }

    private function keyedZone(string $zoneHost): string
    {
        return $this->dqsKey . '.' . $zoneHost;
    }

    private function reverseIpv4(string $ip): ?string
    {
        $parts = explode('.', $ip);

        if (\count($parts) !== 4) {
            return null;
        }

        return implode('.', array_reverse($parts));
    }
}
