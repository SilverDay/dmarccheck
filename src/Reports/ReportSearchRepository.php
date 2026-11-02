<?php

declare(strict_types=1);

namespace App\Reports;

use PDO;

final class ReportSearchRepository
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    /**
     * Returns report-record rows ordered by report-period start and record id.
     *
     * @return list<array{domain: string, source_ip: string, rdns: ?string, asn_org: ?string, label: string, volume: int, dkim_result: string, spf_result: string, disposition: string, date_begin: string, date_end: string, report_id: string}>
     */
    public function search(ReportSearchCriteria $criteria, int $limit): array
    {
        if ($limit < 1 || $limit > 10001) {
            throw new \InvalidArgumentException('Search result limit must be between 1 and 10001.');
        }

        $sql = "SELECT d.domain, INET6_NTOA(rr.source_ip) AS source_ip, ie.rdns, ie.asn_org,
                       COALESCE(ie.label, 'pending') AS label, rr.`count` AS volume,
                       rr.dkim_result, rr.spf_result, rr.disposition, r.date_begin, r.date_end, r.report_id
                  FROM report_records rr
                  JOIN reports r ON r.id = rr.report_id
                  JOIN domains d ON d.id = r.domain_id
                  LEFT JOIN ip_enrichment ie ON ie.source_ip = rr.source_ip
                 WHERE r.date_begin >= ? AND r.date_begin < DATE_ADD(?, INTERVAL 1 DAY)";
        $params = [$criteria->fromDate, $criteria->throughDate];

        if ($criteria->domainId !== null) {
            $sql .= ' AND r.domain_id = ?';
            $params[] = $criteria->domainId;
        }

        if ($criteria->label !== null) {
            $sql .= " AND COALESCE(ie.label, 'pending') = ?";
            $params[] = $criteria->label;
        }

        foreach ([
            'rr.dkim_result' => $criteria->dkimResult,
            'rr.spf_result'  => $criteria->spfResult,
            'rr.disposition' => $criteria->disposition,
        ] as $column => $value) {
            if ($value !== null) {
                $sql .= " AND $column = ?";
                $params[] = $value;
            }
        }

        if ($criteria->asnOrg !== null) {
            $escaped = strtr($criteria->asnOrg, ['!' => '!!', '%' => '!%', '_' => '!_']);
            $sql .= " AND ie.asn_org LIKE ? ESCAPE '!'";
            $params[] = '%' . $escaped . '%';
        }

        $sql .= ' ORDER BY r.date_begin DESC, rr.id DESC LIMIT ' . $limit;

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);

        /** @var list<array<string, mixed>> $rows */
        $rows = $stmt->fetchAll();

        return array_map(
            static fn (array $row): array => [
                'domain'      => (string) $row['domain'],
                'source_ip'   => (string) $row['source_ip'],
                'rdns'        => $row['rdns']    !== null ? (string) $row['rdns'] : null,
                'asn_org'     => $row['asn_org'] !== null ? (string) $row['asn_org'] : null,
                'label'       => (string) $row['label'],
                'volume'      => (int) $row['volume'],
                'dkim_result' => (string) $row['dkim_result'],
                'spf_result'  => (string) $row['spf_result'],
                'disposition' => (string) $row['disposition'],
                'date_begin'  => (string) $row['date_begin'],
                'date_end'    => (string) $row['date_end'],
                'report_id'   => (string) $row['report_id'],
            ],
            $rows
        );
    }

    /** @return list<string> */
    public function labels(): array
    {
        $stmt = $this->pdo->query("SELECT DISTINCT COALESCE(label, 'pending') AS label FROM ip_enrichment ORDER BY label");

        return array_map('strval', $stmt->fetchAll(PDO::FETCH_COLUMN));
    }

    /** @return list<array{id: int, domain: string}> */
    public function domains(): array
    {
        $stmt = $this->pdo->query('SELECT id, domain FROM domains ORDER BY domain');

        return array_map(
            static fn (array $row): array => ['id' => (int) $row['id'], 'domain' => (string) $row['domain']],
            $stmt->fetchAll()
        );
    }
}
