<?php

declare(strict_types=1);

namespace App\Alerting;

use App\Support\Ip;
use DateTimeImmutable;
use PDO;
use RuntimeException;

/**
 * The DB-touching piece of the alerting pass (spec §8): aggregates
 * reports/report_records/ip_enrichment/domains into one AlertContext per
 * domain. Not unit-tested by design, consistent with
 * AnalysisContextBuilder/ReportStore elsewhere in this codebase — the
 * AlertCheck classes it feeds are the tested layer.
 */
final class AlertContextBuilder
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly int $windowDays,
        private readonly int $passRateBaselineDays,
    ) {
    }

    public function build(int $domainId, string $domain): AlertContext
    {
        $domainRow = $this->fetchDomain($domainId);
        $recent    = $this->fetchPassRateWindow($domainId, 0, $this->windowDays);
        $baseline  = $this->fetchPassRateWindow($domainId, $this->windowDays, $this->windowDays + $this->passRateBaselineDays);

        return new AlertContext(
            $domainId,
            $domain,
            new DateTimeImmutable((string) $domainRow['created_at']),
            $this->fetchLastReportReceivedAt($domainId),
            $domainRow['current_published_policy'] !== null ? (string) $domainRow['current_published_policy'] : null,
            $domainRow['approved_baseline_policy'] !== null ? (string) $domainRow['approved_baseline_policy'] : null,
            $this->fetchUnknownIpVolumes($domainId),
            $recent['total'],
            $recent['total'] > 0 ? $recent['passed'] / $recent['total'] * 100 : null,
            $baseline['total'],
            $baseline['total'] > 0 ? $baseline['passed'] / $baseline['total'] * 100 : null,
        );
    }

    /** @return array{created_at: string, current_published_policy: ?string, approved_baseline_policy: ?string} */
    private function fetchDomain(int $domainId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT created_at, current_published_policy, approved_baseline_policy FROM domains WHERE id = ?'
        );
        $stmt->execute([$domainId]);
        $row = $stmt->fetch();

        if ($row === false) {
            throw new RuntimeException("Domain $domainId not found");
        }

        return $row;
    }

    private function fetchLastReportReceivedAt(int $domainId): ?DateTimeImmutable
    {
        $stmt = $this->pdo->prepare('SELECT MAX(received_at) FROM reports WHERE domain_id = ?');
        $stmt->execute([$domainId]);
        $value = $stmt->fetchColumn();

        return \is_string($value) ? new DateTimeImmutable($value) : null;
    }

    /** @return list<UnknownIpVolume> */
    private function fetchUnknownIpVolumes(int $domainId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT rr.source_ip AS source_ip, SUM(rr.`count`) AS total
               FROM report_records rr
               JOIN reports r ON r.id = rr.report_id
               JOIN ip_enrichment ie ON ie.source_ip = rr.source_ip
              WHERE r.domain_id = ? AND r.received_at >= NOW() - INTERVAL ? DAY AND ie.label = \'unknown\'
              GROUP BY rr.source_ip'
        );
        $stmt->bindValue(1, $domainId, PDO::PARAM_INT);
        $stmt->bindValue(2, $this->windowDays, PDO::PARAM_INT);
        $stmt->execute();

        $volumes = [];

        foreach ($stmt as $row) {
            $volumes[] = new UnknownIpVolume(Ip::toString((string) $row['source_ip']), (int) $row['total']);
        }

        return $volumes;
    }

    /** @return array{total: int, passed: int} */
    private function fetchPassRateWindow(int $domainId, int $fromDaysAgo, int $toDaysAgo): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT
                COALESCE(SUM(rr.`count`), 0) AS total,
                COALESCE(SUM(CASE WHEN rr.dkim_result = 'pass' OR rr.spf_result = 'pass' THEN rr.`count` ELSE 0 END), 0) AS passed
               FROM report_records rr
               JOIN reports r ON r.id = rr.report_id
              WHERE r.domain_id = ?
                AND r.received_at >= NOW() - INTERVAL ? DAY
                AND r.received_at <  NOW() - INTERVAL ? DAY"
        );
        $stmt->bindValue(1, $domainId, PDO::PARAM_INT);
        $stmt->bindValue(2, $toDaysAgo, PDO::PARAM_INT);
        $stmt->bindValue(3, $fromDaysAgo, PDO::PARAM_INT);
        $stmt->execute();
        $row = $stmt->fetch();

        return ['total' => (int) $row['total'], 'passed' => (int) $row['passed']];
    }
}
