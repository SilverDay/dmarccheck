<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck;

use App\HealthCheck\OrgDomain;
use PHPUnit\Framework\TestCase;

final class OrgDomainTest extends TestCase
{
    public function testPsdNStopsImmediately(): void
    {
        $dns = new FakeDnsResolver(['_dmarc.example.com' => ['v=DMARC1; p=reject; psd=n']]);

        $result = (new OrgDomain($dns))->resolve('example.com');

        self::assertSame('example.com', $result->organizationalDomain);
        self::assertSame('treewalk', $result->discoveryMethod);
        self::assertSame(['example.com'], $result->queriedNames);
        self::assertCount(1, $dns->txtCalls);
    }

    public function testPsdYResolvesOneLabelBelowAlongTheOriginalDomainsChain(): void
    {
        $dns = new FakeDnsResolver(['_dmarc.psd.tld' => ['v=DMARC1; p=reject; psd=y']]);

        $result = (new OrgDomain($dns))->resolve('a.b.psd.tld');

        self::assertSame('b.psd.tld', $result->organizationalDomain);
        self::assertSame(['a.b.psd.tld', 'b.psd.tld', 'psd.tld'], $result->queriedNames);
    }

    public function testNoPsdAnywhereWalksToLabelExhaustionAndPicksTheOnlyCandidate(): void
    {
        $dns = new FakeDnsResolver(['_dmarc.example.com' => ['v=DMARC1; p=reject; sp=reject']]);

        $result = (new OrgDomain($dns))->resolve('mail.example.com');

        self::assertSame('example.com', $result->organizationalDomain);
        self::assertSame('p=reject; sp=reject', $result->record?->toPolicyString());
        self::assertSame(['mail.example.com', 'example.com', 'com'], $result->queriedNames);
    }

    public function testMultipleRecordsAtATargetAreDiscardedAndTheWalkContinuesPastThem(): void
    {
        $dns = new FakeDnsResolver([
            '_dmarc.mail.example.com' => ['v=DMARC1; p=reject', 'v=DMARC1; p=none'],
            '_dmarc.example.com'      => ['v=DMARC1; p=reject; sp=reject'],
        ]);

        $result = (new OrgDomain($dns))->resolve('mail.example.com');

        self::assertSame('example.com', $result->organizationalDomain);
    }

    public function testNothingFoundAnywhereReturnsNull(): void
    {
        $dns = new FakeDnsResolver();

        $result = (new OrgDomain($dns))->resolve('example.com');

        self::assertNull($result->organizationalDomain);
        self::assertNull($result->record);
        self::assertSame(['example.com', 'com'], $result->queriedNames);
    }

    public function testDeepDomainJumpsToSevenLabelsAndStaysWithinTheEightQueryCap(): void
    {
        $dns = new FakeDnsResolver();

        $result = (new OrgDomain($dns))->resolve('l1.l2.l3.l4.l5.l6.l7.l8.l9');

        self::assertNull($result->organizationalDomain);
        self::assertCount(8, $dns->txtCalls);
        self::assertSame(
            [
                '_dmarc.l1.l2.l3.l4.l5.l6.l7.l8.l9',
                '_dmarc.l3.l4.l5.l6.l7.l8.l9',
                '_dmarc.l4.l5.l6.l7.l8.l9',
                '_dmarc.l5.l6.l7.l8.l9',
                '_dmarc.l6.l7.l8.l9',
                '_dmarc.l7.l8.l9',
                '_dmarc.l8.l9',
                '_dmarc.l9',
            ],
            $dns->txtCalls
        );
    }
}
