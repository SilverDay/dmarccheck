<?php

declare(strict_types=1);

namespace App\Ingest;

use App\Support\Ip;
use PDO;

/**
 * Persistence for parsed reports (spec §3, §4 step 4).
 *
 * Idempotency is enforced at the schema level (unique on
 * domain+reporter+report_id, and on raw_file_hash) — re-running ingestion
 * over an already-processed message is a no-op, not a duplicate.
 */
final class ReportStore
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function alreadyIngested(string $rawFileHash): bool
    {
        $stmt = $this->pdo->prepare('SELECT 1 FROM reports WHERE raw_file_hash = ? LIMIT 1');
        $stmt->execute([$rawFileHash]);

        return $stmt->fetchColumn() !== false;
    }

    /** Returns the domain id, or null when the domain is not onboarded. */
    public function findDomainId(string $domain): ?int
    {
        $stmt = $this->pdo->prepare('SELECT id FROM domains WHERE domain = ? AND active = 1');
        $stmt->execute([strtolower($domain)]);
        $id = $stmt->fetchColumn();

        return $id === false ? null : (int) $id;
    }

    /**
     * @return int|null report id, or null if it was a duplicate
     */
    public function store(ParsedReport $report, int $domainId, string $rawFileHash): ?int
    {
        $this->pdo->beginTransaction();

        try {
            $stmt = $this->pdo->prepare(
                'INSERT INTO reports
                    (domain_id, reporter_org, report_id, date_begin, date_end, raw_file_hash)
                 VALUES (?, ?, ?, ?, ?, ?)'
            );

            $stmt->execute([
                $domainId,
                $report->reporterOrg,
                $report->reportId,
                $report->dateBegin->format('Y-m-d H:i:s'),
                $report->dateEnd->format('Y-m-d H:i:s'),
                $rawFileHash,
            ]);

            $reportRowId = (int) $this->pdo->lastInsertId();

            $recordStmt = $this->pdo->prepare(
                'INSERT INTO report_records
                    (report_id, source_ip, `count`, disposition, dkim_result, spf_result, header_from)
                 VALUES (?, ?, ?, ?, ?, ?, ?)'
            );

            $authStmt = $this->pdo->prepare(
                'INSERT INTO auth_results (record_id, type, domain, selector, result)
                 VALUES (?, ?, ?, ?, ?)'
            );

            foreach ($report->records as $record) {
                $recordStmt->execute([
                    $reportRowId,
                    Ip::toBinary((string) $record['source_ip']),
                    (int) $record['count'],
                    (string) $record['disposition'],
                    (string) $record['dkim_result'],
                    (string) $record['spf_result'],
                    ($record['header_from'] ?? '') !== '' ? $record['header_from'] : null,
                ]);

                $recordRowId = (int) $this->pdo->lastInsertId();

                /** @var list<array<string, string|null>> $authResults */
                $authResults = $record['auth_results'] ?? [];
                foreach ($authResults as $auth) {
                    $authStmt->execute([
                        $recordRowId,
                        $auth['type'],
                        $auth['domain'],
                        $auth['selector'],
                        $auth['result'],
                    ]);
                }

                $this->touchEnrichment((string) $record['source_ip']);
            }

            // Observation only — never overwrites approved_baseline_policy (§10.6)
            $this->pdo->prepare(
                'UPDATE domains SET current_published_policy = ? WHERE id = ?'
            )->execute([$report->policyPublished, $domainId]);

            $this->pdo->commit();

            return $reportRowId;
        } catch (\PDOException $e) {
            $this->pdo->rollBack();

            // 23000 = integrity constraint — a concurrent/duplicate ingest.
            if ($e->getCode() === '23000') {
                return null;
            }

            throw $e;
        }
    }

    /** Seeds the enrichment row; the enrichment worker fills in rDNS/ASN later (§6). */
    private function touchEnrichment(string $ip): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO ip_enrichment (source_ip, last_seen)
             VALUES (?, NOW())
             ON DUPLICATE KEY UPDATE last_seen = NOW()'
        );

        $stmt->execute([Ip::toBinary($ip)]);
    }
}
