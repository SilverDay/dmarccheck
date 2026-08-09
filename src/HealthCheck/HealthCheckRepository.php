<?php

declare(strict_types=1);

namespace App\HealthCheck;

use PDO;

/** Persistence for `health_checks`/`health_check_items` (spec §11.3). */
final class HealthCheckRepository
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function startRun(int $domainId, string $trigger): int
    {
        $stmt = $this->pdo->prepare('INSERT INTO health_checks (domain_id, trigger_) VALUES (?, ?)');
        $stmt->execute([$domainId, $trigger]);

        return (int) $this->pdo->lastInsertId();
    }

    public function recordItem(int $checkId, HealthCheckItemResult $item): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO health_check_items (check_id, category, check_name, status, detail_json)
             VALUES (?, ?, ?, ?, ?)'
        );

        $stmt->execute([
            $checkId,
            $item->category,
            $item->checkName,
            $item->status,
            $item->detail === [] ? null : json_encode($item->detail, JSON_THROW_ON_ERROR),
        ]);
    }

    /**
     * Selectors already observed in this domain's reports — fed into DkimCheck alongside config's list.
     *
     * @return list<string>
     */
    public function observedDkimSelectors(int $domainId): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT DISTINCT ar.selector
               FROM auth_results ar
               JOIN report_records rr ON rr.id = ar.record_id
               JOIN reports r ON r.id = rr.report_id
              WHERE r.domain_id = ? AND ar.type = 'dkim' AND ar.selector IS NOT NULL AND ar.selector != ''"
        );
        $stmt->execute([$domainId]);

        /** @var list<string> */
        return array_map('strval', $stmt->fetchAll(PDO::FETCH_COLUMN));
    }

    /** Observation only — mirrors ReportStore::store(), never touches approved_baseline_policy (§10.6). */
    public function updatePublishedPolicy(int $domainId, string $policyString): void
    {
        $stmt = $this->pdo->prepare('UPDATE domains SET current_published_policy = ? WHERE id = ?');
        $stmt->execute([$policyString, $domainId]);
    }

    /** The most recent health check run for a domain, with its items, for the dashboard drill-down (spec §7.2). */
    public function latestForDomain(int $domainId): ?HealthCheckSummary
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, run_at, trigger_ FROM health_checks WHERE domain_id = ? ORDER BY run_at DESC LIMIT 1'
        );
        $stmt->execute([$domainId]);
        $run = $stmt->fetch();

        if ($run === false) {
            return null;
        }

        $stmt = $this->pdo->prepare(
            'SELECT category, check_name, status, detail_json FROM health_check_items WHERE check_id = ? ORDER BY category, check_name'
        );
        $stmt->execute([(int) $run['id']]);

        $items = [];

        foreach ($stmt as $row) {
            /** @var mixed $detail */
            $detail  = $row['detail_json'] !== null ? json_decode((string) $row['detail_json'], true) : [];
            $items[] = new HealthCheckItemResult(
                (string) $row['category'],
                (string) $row['check_name'],
                (string) $row['status'],
                \is_array($detail) ? $detail : [],
            );
        }

        return new HealthCheckSummary((string) $run['run_at'], (string) $run['trigger_'], $items);
    }
}
