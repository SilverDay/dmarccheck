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

    /**
     * The latest health-check run's status tally per active domain — a
     * lighter cross-domain query than latestForDomain(), which returns
     * full item detail for one domain's drill-down. Feeds the overview
     * dashboard's posture-card grade (spec §7.1/§11).
     *
     * @return array<int, HealthCheckLatestRun> keyed by domain_id
     */
    public function latestForAllDomains(): array
    {
        $stmt = $this->pdo->query(
            "SELECT hc.domain_id, hc.run_at, hc.trigger_, hci.status, COUNT(*) AS cnt
               FROM health_checks hc
               JOIN (SELECT domain_id, MAX(id) AS id FROM health_checks GROUP BY domain_id) latest
                 ON latest.domain_id = hc.domain_id AND latest.id = hc.id
               JOIN domains d ON d.id = hc.domain_id AND d.active = 1
               JOIN health_check_items hci ON hci.check_id = hc.id
              GROUP BY hc.domain_id, hc.run_at, hc.trigger_, hci.status"
        );

        /** @var array<int, array{runAt: string, trigger: string, tally: array<string, int>}> $byDomain */
        $byDomain = [];

        foreach ($stmt as $row) {
            $domainId = (int) $row['domain_id'];

            $byDomain[$domainId] ??= [
                'runAt'   => (string) $row['run_at'],
                'trigger' => (string) $row['trigger_'],
                'tally'   => [],
            ];

            $byDomain[$domainId]['tally'][(string) $row['status']] = (int) $row['cnt'];
        }

        return array_map(
            static fn (array $r): HealthCheckLatestRun => new HealthCheckLatestRun($r['runAt'], $r['trigger'], $r['tally']),
            $byDomain
        );
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
