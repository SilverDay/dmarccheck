<?php

declare(strict_types=1);

namespace App\Tests\Enrichment;

use App\Enrichment\KnownSenderMatcher;
use PHPUnit\Framework\TestCase;

final class KnownSenderMatcherTest extends TestCase
{
    public function testMatchesExactIp(): void
    {
        $matcher = new KnownSenderMatcher([
            ['ip_or_cidr' => '203.0.113.5', 'label' => 'Corporate relay'],
        ]);

        self::assertSame('Corporate relay', $matcher->match('203.0.113.5'));
        self::assertNull($matcher->match('203.0.113.6'));
    }

    public function testMatchesIpv4Cidr(): void
    {
        $matcher = new KnownSenderMatcher([
            ['ip_or_cidr' => '198.51.100.0/24', 'label' => 'ESP block'],
        ]);

        self::assertSame('ESP block', $matcher->match('198.51.100.42'));
        self::assertNull($matcher->match('198.51.101.42'));
    }

    public function testMatchesIpv6Cidr(): void
    {
        $matcher = new KnownSenderMatcher([
            ['ip_or_cidr' => '2001:db8::/32', 'label' => 'IPv6 relay'],
        ]);

        self::assertSame('IPv6 relay', $matcher->match('2001:db8::1'));
        self::assertNull($matcher->match('2001:db9::1'));
    }

    public function testFirstMatchWinsAndNoRulesMatchesNothing(): void
    {
        $matcher = new KnownSenderMatcher([
            ['ip_or_cidr' => '10.0.0.0/8', 'label' => 'First'],
            ['ip_or_cidr' => '10.0.0.0/16', 'label' => 'Second'],
        ]);

        self::assertSame('First', $matcher->match('10.0.1.1'));

        $empty = new KnownSenderMatcher([]);
        self::assertNull($empty->match('1.2.3.4'));
    }

    public function testMatchForDomainMatchesGlobalRule(): void
    {
        $matcher = new KnownSenderMatcher([
            ['ip_or_cidr' => '203.0.113.5', 'label' => 'Global relay', 'domain_id' => null],
        ]);

        self::assertSame('Global relay', $matcher->matchForDomain('203.0.113.5', 1));
        self::assertSame('Global relay', $matcher->matchForDomain('203.0.113.5', 2));
    }

    public function testMatchForDomainMatchesOnlyItsOwnDomain(): void
    {
        $matcher = new KnownSenderMatcher([
            ['ip_or_cidr' => '203.0.113.5', 'label' => 'Domain A relay', 'domain_id' => 1],
        ]);

        self::assertSame('Domain A relay', $matcher->matchForDomain('203.0.113.5', 1));
        self::assertNull($matcher->matchForDomain('203.0.113.5', 2));
    }

    public function testMatchForDomainFallsThroughToAGlobalRuleAfterADomainMismatch(): void
    {
        $matcher = new KnownSenderMatcher([
            ['ip_or_cidr' => '203.0.113.5', 'label' => 'Domain A relay', 'domain_id' => 1],
            ['ip_or_cidr' => '203.0.113.5', 'label' => 'Global fallback', 'domain_id' => null],
        ]);

        self::assertSame('Global fallback', $matcher->matchForDomain('203.0.113.5', 2));
    }

    public function testMatchForDomainMissingKeyDefaultsToGlobal(): void
    {
        // Rows built without an explicit domain_id key (e.g. older call sites) behave as global.
        $matcher = new KnownSenderMatcher([
            ['ip_or_cidr' => '203.0.113.5', 'label' => 'No domain_id key'],
        ]);

        self::assertSame('No domain_id key', $matcher->matchForDomain('203.0.113.5', 42));
    }
}
