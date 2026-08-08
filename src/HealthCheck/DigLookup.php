<?php

declare(strict_types=1);

namespace App\HealthCheck;

/**
 * The two things PHP's dns_get_record() can't do: DS records (no DNS_DS
 * constant exists) and resolver-pinned queries (DNSBL lookups must go
 * through a specific attributable resolver — spec §11.6). SystemDigLookup
 * is the real implementation; this interface exists so DnssecCheck/
 * DnsblCheck are unit-testable with a fake, matching DnsResolver's pattern.
 */
interface DigLookup
{
    /**
     * @return list<string>|null null means the query itself failed/timed
     *     out — distinct from an empty list (queried fine, no records)
     */
    public function query(string $name, string $type): ?array;
}
