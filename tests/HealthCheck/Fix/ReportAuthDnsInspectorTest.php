<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck\Fix;

use App\HealthCheck\DnsResolver;
use App\HealthCheck\Fix\ReportAuthDnsInspector;
use PHPUnit\Framework\TestCase;

final class ReportAuthDnsInspectorTest extends TestCase
{
    public function testSpfInspectionUsesTheSharedLookupCounter(): void
    {
        $inspector = new ReportAuthDnsInspector(new ReportAuthDnsFake([
            'example.com' => ['v=spf1 include:_spf.example.net -all'],
        ]));

        self::assertSame([
            'status'       => 'pass',
            'record'       => 'v=spf1 include:_spf.example.net -all',
            'records'      => [],
            'lookup_count' => 1,
            'issues'       => [],
            'reason'       => null,
        ], $inspector->inspectSpf('example.com'));
    }

    public function testDkimInspectionFetchesTheObservedSelectorRecord(): void
    {
        $inspector = new ReportAuthDnsInspector(new ReportAuthDnsFake([
            's1._domainkey.example.com' => ['v=DKIM1; p=public-key'],
        ]));

        self::assertSame([
            'name'    => 's1._domainkey.example.com',
            'records' => ['v=DKIM1; p=public-key'],
        ], $inspector->inspectDkim('Example.COM.', 's1'));
    }

    public function testInvalidDkimTargetsAreNotQueried(): void
    {
        $dns       = new ReportAuthDnsFake([]);
        $inspector = new ReportAuthDnsInspector($dns);

        self::assertNull($inspector->inspectDkim('example.com', 'selector.example'));
        self::assertSame('error', $inspector->inspectSpf('bad_domain')['status']);
        self::assertSame([], $dns->queried);
    }
}

/** @internal */
final class ReportAuthDnsFake implements DnsResolver
{
    /** @var list<string> */
    public array $queried = [];

    /** @param array<string, list<string>> $txtRecords */
    public function __construct(private readonly array $txtRecords)
    {
    }

    public function txt(string $name): array
    {
        $this->queried[] = $name;

        return $this->txtRecords[$name] ?? [];
    }

    public function mx(string $domain): array
    {
        return [];
    }

    public function a(string $name): array
    {
        return [];
    }

    public function aaaa(string $name): array
    {
        return [];
    }
}
