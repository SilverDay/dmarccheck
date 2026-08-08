<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck;

use App\HealthCheck\DmarcRecord;
use PHPUnit\Framework\TestCase;

final class DmarcRecordTest extends TestCase
{
    public function testNonDmarcRecordReturnsNull(): void
    {
        self::assertNull(DmarcRecord::parse('v=spf1 -all'));
    }

    public function testParsesTags(): void
    {
        $record = DmarcRecord::parse('v=DMARC1; p=reject; sp=quarantine; pct=50; adkim=s; aspf=r');

        self::assertNotNull($record);
        self::assertSame('reject', $record->policy);
        self::assertSame('quarantine', $record->subdomainPolicy);
        self::assertSame(50, $record->pct);
        self::assertSame('s', $record->adkim);
        self::assertSame('r', $record->aspf);
    }

    public function testParsesMultipleRuaAddressesAndStripsSizeLimit(): void
    {
        $record = DmarcRecord::parse('v=DMARC1; p=reject; rua=mailto:a@example.com!10m,mailto:b@other.com');

        self::assertNotNull($record);
        self::assertSame(['a@example.com', 'b@other.com'], $record->ruaAddresses);
        self::assertSame(['example.com', 'other.com'], $record->ruaDomains());
    }

    public function testToPolicyStringMatchesReportParserFormat(): void
    {
        $record = DmarcRecord::parse('v=DMARC1; p=reject; sp=reject');

        self::assertNotNull($record);
        self::assertSame('p=reject; sp=reject', $record->toPolicyString());
    }
}
