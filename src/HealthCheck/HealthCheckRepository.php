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
}
