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

    /** DMARCbis (RFC 9989) additions — docs/feature-dmarcbis.md Phase 1. */
    public function testParsesDmarcbisTags(): void
    {
        $record = DmarcRecord::parse('v=DMARC1; p=reject; np=reject; psd=n; t=y; rf=afrf; ri=86400; fo=1:d');

        self::assertNotNull($record);
        self::assertSame('reject', $record->nonExistentSubdomainPolicy);
        self::assertSame('n', $record->psd);
        self::assertSame('y', $record->testing);
        self::assertSame('afrf', $record->reportFormat);
        self::assertSame('86400', $record->reportInterval);
        self::assertSame('1:d', $record->failureOptions);
        self::assertStringContainsString('psd=n', $record->toPolicyString());
    }

    public function testDmarcbisTagsAreNullWhenAbsent(): void
    {
        $record = DmarcRecord::parse('v=DMARC1; p=reject');

        self::assertNotNull($record);
        self::assertNull($record->nonExistentSubdomainPolicy);
        self::assertNull($record->psd);
        self::assertNull($record->testing);
        self::assertNull($record->reportFormat);
        self::assertNull($record->reportInterval);
        self::assertNull($record->failureOptions);
    }

    public function testDistinguishesPctFromTestingModeAndValidatesNewTagValues(): void
    {
        $record = DmarcRecord::parse('v=DMARC1; p=reject; pct=25; np=quarantine; psd=y; t=y');

        self::assertNotNull($record);
        self::assertSame(25, $record->pct);
        self::assertSame('y', $record->testing);
        self::assertSame([], $record->invalidDmarcbisTags());

        $invalid = DmarcRecord::parse('v=DMARC1; p=reject; np=full; psd=u; t=maybe');

        self::assertNotNull($invalid);
        self::assertSame(['np' => 'full', 'psd' => 'u', 't' => 'maybe'], $invalid->invalidDmarcbisTags());
    }

    public function testToPolicyStringIncludesDmarcbisTagsInReportParserOrder(): void
    {
        $record = DmarcRecord::parse('v=DMARC1; p=reject; sp=reject; np=reject; pct=50; adkim=s; aspf=r; t=y');

        self::assertNotNull($record);
        self::assertSame('p=reject; sp=reject; np=reject; pct=50; adkim=s; aspf=r; t=y', $record->toPolicyString());
    }
}
