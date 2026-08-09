<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck;

use App\HealthCheck\Checks\DnsblCheck;
use App\HealthCheck\HealthCheckItemResult;
use App\HealthCheck\MxRecord;
use PHPUnit\Framework\TestCase;

final class DnsblCheckTest extends TestCase
{
    public function testUnconfiguredKeyReportsErrorPerZone(): void
    {
        $check = new DnsblCheck(
            new FakeDnsResolver(),
            new FakeDigLookup(),
            '',
            ['zen' => 'zen.dq.spamhaus.net', 'dbl' => 'dbl.dq.spamhaus.net'],
        );

        $results = $check->run('example.com');

        self::assertCount(2, $results);

        foreach ($results as $result) {
            self::assertSame(HealthCheckItemResult::ERROR, $result->status);
        }
    }

    public function testDomainZoneIsOnlyQueriedByDomainNameNotByMxIp(): void
    {
        $dig = new FakeDigLookup(['example.com.KEY.dbl.dq.spamhaus.net:A' => []]);
        $dns = new FakeDnsResolver(
            mxRecords: ['example.com' => [new MxRecord(10, 'mail.example.com')]],
            aRecords: ['mail.example.com' => ['192.0.2.1']],
        );
        $check = new DnsblCheck($dns, $dig, 'KEY', ['dbl' => 'dbl.dq.spamhaus.net']);

        $results = $check->run('example.com');

        self::assertCount(1, $results);
        self::assertSame('dnsbl_dbl', $results[0]->checkName);
        self::assertArrayHasKey('domain', $results[0]->detail);
    }

    public function testIpZoneIsOnlyQueriedByReversedMxIpNotByDomainName(): void
    {
        $dig = new FakeDigLookup(['1.2.0.192.KEY.zen.dq.spamhaus.net:A' => []]);
        $dns = new FakeDnsResolver(
            mxRecords: ['example.com' => [new MxRecord(10, 'mail.example.com')]],
            aRecords: ['mail.example.com' => ['192.0.2.1']],
        );
        $check = new DnsblCheck($dns, $dig, 'KEY', ['zen' => 'zen.dq.spamhaus.net']);

        $results = $check->run('example.com');

        self::assertCount(1, $results);
        self::assertSame('dnsbl_zen', $results[0]->checkName);
        self::assertArrayHasKey('ip', $results[0]->detail);
    }

    /** Both zones configured together: exactly one dbl (domain) result and one zen (IP) result, never four. */
    public function testDomainAndIpZonesEachProduceExactlyOneResult(): void
    {
        $dig = new FakeDigLookup([
            'example.com.KEY.dbl.dq.spamhaus.net:A' => [],
            '1.2.0.192.KEY.zen.dq.spamhaus.net:A'   => [],
        ]);
        $dns = new FakeDnsResolver(
            mxRecords: ['example.com' => [new MxRecord(10, 'mail.example.com')]],
            aRecords: ['mail.example.com' => ['192.0.2.1']],
        );
        $check = new DnsblCheck($dns, $dig, 'KEY', ['zen' => 'zen.dq.spamhaus.net', 'dbl' => 'dbl.dq.spamhaus.net']);

        $results = $check->run('example.com');

        self::assertSame(['dnsbl_dbl', 'dnsbl_zen'], array_map(static fn ($r) => $r->checkName, $results));
    }

    public function testAListedAnswerFails(): void
    {
        $dig = new FakeDigLookup(['1.2.0.192.KEY.zen.dq.spamhaus.net:A' => ['127.0.0.4']]);
        $dns = new FakeDnsResolver(
            mxRecords: ['example.com' => [new MxRecord(10, 'mail.example.com')]],
            aRecords: ['mail.example.com' => ['192.0.2.1']],
        );
        $check = new DnsblCheck($dns, $dig, 'KEY', ['zen' => 'zen.dq.spamhaus.net']);

        $results = $check->run('example.com');

        self::assertSame(HealthCheckItemResult::FAIL, $results[0]->status);
    }

    public function testABlockedQuerySentinelIsErrorNotAPass(): void
    {
        $dig   = new FakeDigLookup(['example.com.KEY.dbl.dq.spamhaus.net:A' => ['127.255.255.254']]);
        $check = new DnsblCheck(new FakeDnsResolver(), $dig, 'KEY', ['dbl' => 'dbl.dq.spamhaus.net']);

        $results = $check->run('example.com');

        self::assertSame(HealthCheckItemResult::ERROR, $results[0]->status);
    }
}
