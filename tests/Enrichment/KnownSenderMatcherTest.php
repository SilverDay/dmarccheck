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
}
