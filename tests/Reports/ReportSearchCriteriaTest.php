<?php

declare(strict_types=1);

namespace App\Tests\Reports;

use App\Reports\ReportSearchCriteria;
use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class ReportSearchCriteriaTest extends TestCase
{
    public function testPresetRangesAreInclusiveAndAllowDomainWideScope(): void
    {
        $criteria = ReportSearchCriteria::fromQuery(
            ['domain' => 'all', 'range' => '7'],
            new DateTimeImmutable('2026-11-02')
        );

        self::assertNull($criteria->domainId);
        self::assertSame('2026-10-27', $criteria->fromDate);
        self::assertSame('2026-11-02', $criteria->throughDate);
    }

    public function testCustomRangeAndAllFiltersAreParsed(): void
    {
        $criteria = ReportSearchCriteria::fromQuery([
            'domain'      => '12',
            'range'       => 'custom',
            'from'        => '2026-01-01',
            'to'          => '2026-02-01',
            'label'       => 'Corporate relay',
            'dkim'        => 'fail',
            'spf'         => 'pass',
            'disposition' => 'quarantine',
            'asn_org'     => 'Example Network',
        ]);

        self::assertSame(12, $criteria->domainId);
        self::assertSame('2026-01-01', $criteria->fromDate);
        self::assertSame('2026-02-01', $criteria->throughDate);
        self::assertSame('Corporate relay', $criteria->label);
        self::assertSame('fail', $criteria->dkimResult);
        self::assertSame('pass', $criteria->spfResult);
        self::assertSame('quarantine', $criteria->disposition);
        self::assertSame('Example Network', $criteria->asnOrg);
    }

    public function testInvalidDatesAndReversedOrOversizedRangesAreRejected(): void
    {
        foreach ([
            ['range' => 'custom', 'from' => '2026-02-30', 'to' => '2026-03-01'],
            ['range' => 'custom', 'from' => '2026-03-02', 'to' => '2026-03-01'],
            ['range' => 'custom', 'from' => '2025-01-01', 'to' => '2026-01-02'],
        ] as $query) {
            try {
                ReportSearchCriteria::fromQuery($query);
                self::fail('Expected invalid search criteria to throw.');
            } catch (InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }

    public function testMalformedFilterTypesAndUnsupportedValuesAreRejected(): void
    {
        foreach ([
            ['domain' => ['1']],
            ['dkim'        => 'neutral'],
            ['spf'         => 'pass,fail'],
            ['disposition' => 'accept'],
            ['label'       => str_repeat('x', 65)],
            ['asn_org'     => str_repeat('x', 101)],
        ] as $query) {
            try {
                ReportSearchCriteria::fromQuery($query);
                self::fail('Expected invalid search criteria to throw.');
            } catch (InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }
}
