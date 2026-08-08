<?php

declare(strict_types=1);

namespace App\Tests\Enrichment;

use App\Enrichment\AsnInfo;
use App\Enrichment\AsnLookup;
use App\Enrichment\EnrichmentService;
use App\Enrichment\EspHeuristic;
use App\Enrichment\KnownSenderMatcher;
use App\Enrichment\RdnsResolver;
use PHPUnit\Framework\TestCase;

final class EnrichmentServiceTest extends TestCase
{
    public function testKnownSenderTakesPrecedenceOverAsnHeuristic(): void
    {
        $service = new EnrichmentService(
            $this->fakeRdns('mail.example.com'),
            $this->fakeAsn(15169, 'Google LLC'),
            new KnownSenderMatcher([['ip_or_cidr' => '203.0.113.5', 'label' => 'Corporate relay']]),
            new EspHeuristic([15169 => 'Google']),
        );

        $result = $service->enrich('203.0.113.5');

        self::assertSame('Corporate relay', $result->label);
        self::assertSame('mail.example.com', $result->rdns);
        self::assertSame(15169, $result->asn);
        self::assertSame('Google LLC', $result->asnOrg);
    }

    public function testFallsBackToAsnHeuristicWhenNoKnownSenderMatches(): void
    {
        $service = new EnrichmentService(
            $this->fakeRdns(null),
            $this->fakeAsn(15169, 'Google LLC'),
            new KnownSenderMatcher([]),
            new EspHeuristic([15169 => 'Google']),
        );

        $result = $service->enrich('8.8.8.8');

        self::assertSame('Google', $result->label);
        self::assertNull($result->rdns);
    }

    public function testFallsBackToUnknownWhenNothingMatches(): void
    {
        $service = new EnrichmentService(
            $this->fakeRdns(null),
            $this->fakeAsn(null, null),
            new KnownSenderMatcher([]),
            new EspHeuristic([]),
        );

        $result = $service->enrich('198.51.100.1');

        self::assertSame('unknown', $result->label);
        self::assertNull($result->asn);
        self::assertNull($result->asnOrg);
    }

    private function fakeRdns(?string $hostname): RdnsResolver
    {
        return new class ($hostname) implements RdnsResolver {
            public function __construct(private readonly ?string $hostname)
            {
            }

            public function resolve(string $ip): ?string
            {
                return $this->hostname;
            }
        };
    }

    private function fakeAsn(?int $asn, ?string $org): AsnLookup
    {
        return new class ($asn, $org) implements AsnLookup {
            public function __construct(private readonly ?int $asn, private readonly ?string $org)
            {
            }

            public function lookup(string $ip): ?AsnInfo
            {
                return $this->asn === null || $this->org === null ? null : new AsnInfo($this->asn, $this->org);
            }
        };
    }
}
