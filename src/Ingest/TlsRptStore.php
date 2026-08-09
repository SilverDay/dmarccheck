<?php

declare(strict_types=1);

namespace App\Ingest;

use App\Support\Ip;
use PDO;
use PDOException;

/**
 * Persistence for parsed TLS-RPT reports (spec §3.7, §12).
 *
 * Deliberately doesn't share code with ReportStore: findDomainId() is a
 * textually identical 2-line query, duplicated rather than extracted,
 * since a shared helper isn't worth touching a stable, untested-by-design
 * file for. Unlike ReportStore::store(), this never touches
 * domains.current_published_policy or ip_enrichment — TLS-RPT's
 * policy-type isn't the same concept as DMARC's p=/sp=, and
 * sending-mta-ip isn't reviewed as an enrichment "source" here.
 */
final class TlsRptStore
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function alreadyIngested(string $rawFileHash): bool
    {
        $stmt = $this->pdo->prepare('SELECT 1 FROM tls_rpt_reports WHERE raw_file_hash = ? LIMIT 1');
        $stmt->execute([$rawFileHash]);

        return $stmt->fetchColumn() !== false;
    }

    /**
     * A TLS-RPT file can name multiple domains via `policies[]` — resolve
     * and store per matched domain, skip (never fail the whole file for)
     * unmanaged ones. All-or-nothing per matched policy, in one transaction.
     */
    public function store(ParsedTlsRptReport $report, string $rawFileHash): TlsRptStoreResult
    {
        $matched        = [];
        $skippedDomains = [];

        foreach ($report->policies as $policy) {
            $domain   = (string) $policy['domain'];
            $domainId = $this->findDomainId($domain);

            if ($domainId === null) {
                $skippedDomains[] = $domain;

                continue;
            }

            $matched[] = ['domain_id' => $domainId, 'policy' => $policy];
        }

        if ($matched === []) {
            return new TlsRptStoreResult([], $skippedDomains);
        }

        $this->pdo->beginTransaction();

        try {
            $reportStmt = $this->pdo->prepare(
                'INSERT INTO tls_rpt_reports
                    (domain_id, organization_name, report_id, date_begin, date_end,
                     policy_type, policy_string, mx_host, success_count, failure_count, raw_file_hash)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
            );

            $recordStmt = $this->pdo->prepare(
                'INSERT INTO tls_rpt_records
                    (tls_rpt_report_id, result_type, sending_mta_ip, receiving_mx_hostname,
                     receiving_mx_helo, receiving_ip, failed_session_count, additional_information, failure_reason_code)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
            );

            $storedIds = [];

            foreach ($matched as $m) {
                /** @var array<string, mixed> $policy */
                $policy = $m['policy'];

                $reportStmt->execute([
                    $m['domain_id'],
                    $report->organizationName,
                    $report->reportId,
                    $report->dateBegin->format('Y-m-d H:i:s'),
                    $report->dateEnd->format('Y-m-d H:i:s'),
                    $policy['policy_type'],
                    $policy['policy_string'],
                    $policy['mx_host'],
                    $policy['success_count'],
                    $policy['failure_count'],
                    $rawFileHash,
                ]);

                $reportRowId = (int) $this->pdo->lastInsertId();
                $storedIds[] = $reportRowId;

                /** @var list<array<string, mixed>> $failureDetails */
                $failureDetails = $policy['failure_details'];

                foreach ($failureDetails as $detail) {
                    $recordStmt->execute([
                        $reportRowId,
                        $detail['result_type'],
                        $detail['sending_mta_ip'] !== null ? Ip::toBinary((string) $detail['sending_mta_ip']) : null,
                        $detail['receiving_mx_hostname'],
                        $detail['receiving_mx_helo'],
                        $detail['receiving_ip'] !== null ? Ip::toBinary((string) $detail['receiving_ip']) : null,
                        $detail['failed_session_count'],
                        $detail['additional_information'],
                        $detail['failure_reason_code'],
                    ]);
                }
            }

            $this->pdo->commit();

            return new TlsRptStoreResult($storedIds, $skippedDomains);
        } catch (PDOException $e) {
            $this->pdo->rollBack();

            // 23000 = integrity constraint — a concurrent/duplicate ingest.
            if ($e->getCode() === '23000') {
                return new TlsRptStoreResult([], $skippedDomains);
            }

            throw $e;
        }
    }

    private function findDomainId(string $domain): ?int
    {
        $stmt = $this->pdo->prepare('SELECT id FROM domains WHERE domain = ? AND active = 1');
        $stmt->execute([strtolower($domain)]);
        $id = $stmt->fetchColumn();

        return $id === false ? null : (int) $id;
    }
}
