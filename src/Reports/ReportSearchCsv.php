<?php

declare(strict_types=1);

namespace App\Reports;

final class ReportSearchCsv
{
    private const array HEADERS = [
        'Domain',
        'Source IP',
        'rDNS',
        'ASN organization',
        'Label',
        'Volume',
        'DKIM result',
        'SPF result',
        'Disposition',
        'Report period start',
        'Report period end',
        'Report ID',
    ];

    /**
     * @param list<array{domain: string, source_ip: string, rdns: ?string, asn_org: ?string, label: string, volume: int, dkim_result: string, spf_result: string, disposition: string, date_begin: string, date_end: string, report_id: string}> $rows
     */
    public static function render(array $rows): string
    {
        $stream = fopen('php://temp', 'r+');

        if ($stream === false) {
            throw new \RuntimeException('Unable to allocate a temporary CSV stream.');
        }

        fputcsv($stream, self::HEADERS, ',', '"', '', "\r\n");

        foreach ($rows as $row) {
            fputcsv($stream, [
                self::spreadsheetSafe($row['domain']),
                self::spreadsheetSafe($row['source_ip']),
                self::spreadsheetSafe($row['rdns'] ?? ''),
                self::spreadsheetSafe($row['asn_org'] ?? ''),
                self::spreadsheetSafe($row['label']),
                $row['volume'],
                self::spreadsheetSafe($row['dkim_result']),
                self::spreadsheetSafe($row['spf_result']),
                self::spreadsheetSafe($row['disposition']),
                self::spreadsheetSafe($row['date_begin']),
                self::spreadsheetSafe($row['date_end']),
                self::spreadsheetSafe($row['report_id']),
            ], ',', '"', '', "\r\n");
        }

        rewind($stream);
        $csv = stream_get_contents($stream);
        fclose($stream);

        if ($csv === false) {
            throw new \RuntimeException('Unable to read the generated CSV export.');
        }

        return $csv;
    }

    private static function spreadsheetSafe(string $value): string
    {
        return preg_match('/^[\x00-\x20]*[=+\-@]/', $value) === 1 ? "'" . $value : $value;
    }
}
