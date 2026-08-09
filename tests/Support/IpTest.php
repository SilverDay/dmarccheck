<?php

declare(strict_types=1);

namespace App\Tests\Support;

use App\Support\Ip;
use PHPUnit\Framework\TestCase;

/**
 * Scoped to isValidIpOrCidr() only — toBinary()/toString()/inCidr() have
 * no direct test coverage and aren't backfilled here.
 */
final class IpTest extends TestCase
{
    public function testAcceptsABareIpv4Address(): void
    {
        self::assertTrue(Ip::isValidIpOrCidr('203.0.113.5'));
    }

    public function testAcceptsABareIpv6Address(): void
    {
        self::assertTrue(Ip::isValidIpOrCidr('2001:db8::1'));
    }

    public function testAcceptsAnIpv4Cidr(): void
    {
        self::assertTrue(Ip::isValidIpOrCidr('203.0.113.0/24'));
    }

    public function testAcceptsAnIpv6Cidr(): void
    {
        self::assertTrue(Ip::isValidIpOrCidr('2001:db8::/32'));
    }

    public function testRejectsAnInvalidIp(): void
    {
        self::assertFalse(Ip::isValidIpOrCidr('not-an-ip'));
    }

    public function testRejectsANonNumericPrefix(): void
    {
        self::assertFalse(Ip::isValidIpOrCidr('203.0.113.0/abc'));
    }

    public function testRejectsAnIpv4PrefixOver32(): void
    {
        self::assertFalse(Ip::isValidIpOrCidr('203.0.113.0/33'));
    }

    public function testRejectsAnIpv6PrefixOver128(): void
    {
        self::assertFalse(Ip::isValidIpOrCidr('2001:db8::/129'));
    }

    public function testRejectsMalformedInput(): void
    {
        self::assertFalse(Ip::isValidIpOrCidr(''));
        self::assertFalse(Ip::isValidIpOrCidr('/24'));
    }
}
