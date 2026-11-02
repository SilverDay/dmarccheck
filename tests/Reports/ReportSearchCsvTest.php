<?php

declare(strict_types=1);

namespace App\Tests\Reports;

use App\Reports\ReportSearchCsv;
use PHPUnit\Framework\TestCase;

final class ReportSearchCsvTest extends TestCase
{
    public function testExportHasSpecifiedColumnShapeAndEscapesSpreadsheetFormulas(): void
    {
        $csv = ReportSearchCsv::render([[
            'domain'      => '=HYPERLINK("https://example.test")',
            'source_ip'   => '192.0.2.1',
            'rdns'        => 'mx.example.test',
            'asn_org'     => 'Example, Inc.',
            'label'       => 'unknown',
            'volume'      => 4,
            'dkim_result' => 'fail',
            'spf_result'  => 'pass',
            'disposition' => 'reject',
            'date_begin'  => '2026-01-01 00:00:00',
            'date_end'    => '2026-01-02 00:00:00',
            'report_id'   => '+SUM(1,1)',
        ]]);
        $lines  = explode("\r\n", trim($csv));
        $header = str_getcsv($lines[0]);
        $row    = str_getcsv($lines[1]);

        self::assertSame([
            'Domain', 'Source IP', 'rDNS', 'ASN organization', 'Label', 'Volume',
            'DKIM result', 'SPF result', 'Disposition', 'Report period start',
            'Report period end', 'Report ID',
        ], $header);
        self::assertCount(12, $row);
        self::assertSame('\'=HYPERLINK("https://example.test")', $row[0]);
        self::assertSame('Example, Inc.', $row[3]);
        self::assertSame('4', $row[5]);
        self::assertSame("'+SUM(1,1)", $row[11]);
    }

    public function testEmptyResultsStillProduceHeaders(): void
    {
        $lines = explode("\r\n", trim(ReportSearchCsv::render([])));

        self::assertCount(1, $lines);
        self::assertStringContainsString('Report ID', $lines[0]);
    }
}
