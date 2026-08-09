<?php

declare(strict_types=1);

namespace App\Recommendation;

use PDO;

/**
 * Persistence for `recommendations` (spec §10.5). The schema has no
 * dedicated "subject" column, so the reconciliation key is round-tripped
 * through a reserved `_subject` key inside `evidence_json` — set here at
 * write time, read back here at fetch time; `RuleFinding::$evidence`
 * itself never needs to know about this.
 */
final class RecommendationRepository
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    /** @return list<ExistingRecommendation> */
    public function openAndAcknowledged(int $domainId): array
    {
        return $this->fetchByStates($domainId, ['open', 'acknowledged']);
    }

    /**
     * Full row data for the dashboard drill-down (spec §7.2) —
     * openAndAcknowledged() only carries reconciliation identity.
     *
     * @return list<RecommendationRow>
     */
    public function forDisplay(int $domainId): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT id, rule_id, severity, evidence_json, first_seen, last_seen, state
               FROM recommendations
              WHERE domain_id = ? AND state IN ('open', 'acknowledged')
              ORDER BY FIELD(severity, 'high', 'medium', 'low', 'info'), last_seen DESC"
        );
        $stmt->execute([$domainId]);

        $rows = [];

        foreach ($stmt as $row) {
            $rows[] = $this->mapRow($row);
        }

        return $rows;
    }

    /**
     * Open+acknowledged recommendation counts by severity, across all
     * active domains — the overview dashboard's posture-card grid
     * (spec §7.1). Same open+acknowledged state definition as
     * forDisplay(); acknowledged isn't visually distinguished anywhere in
     * the UI today, so it stays folded into "open" here too.
     *
     * @return array<int, array<string, int>> domain_id => severity => count
     */
    public function countsBySeverityForAllDomains(): array
    {
        $stmt = $this->pdo->query(
            "SELECT rec.domain_id, rec.severity, COUNT(*) AS cnt
               FROM recommendations rec
               JOIN domains d ON d.id = rec.domain_id AND d.active = 1
              WHERE rec.state IN ('open', 'acknowledged')
              GROUP BY rec.domain_id, rec.severity"
        );

        $counts = [];

        foreach ($stmt as $row) {
            $counts[(int) $row['domain_id']][(string) $row['severity']] = (int) $row['cnt'];
        }

        return $counts;
    }

    /**
     * Highest-severity open+acknowledged recommendations across all
     * active domains, filtered to high/medium — the overview dashboard's
     * Attention panel (spec §7.1). Deliberately narrower than
     * forDisplay(): low/info recommendations aren't "what needs me
     * today" and already have a home on the per-domain drill-down.
     *
     * @return list<array{domain: string, row: RecommendationRow}>
     */
    public function topOpenAcrossDomains(int $limit): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT d.domain, rec.id, rec.rule_id, rec.severity, rec.evidence_json, rec.first_seen, rec.last_seen, rec.state
               FROM recommendations rec
               JOIN domains d ON d.id = rec.domain_id AND d.active = 1
              WHERE rec.state IN ('open', 'acknowledged') AND rec.severity IN ('high', 'medium')
              ORDER BY FIELD(rec.severity, 'high', 'medium'), rec.last_seen DESC
              LIMIT ?"
        );
        $stmt->bindValue(1, $limit, PDO::PARAM_INT);
        $stmt->execute();

        $rows = [];

        foreach ($stmt as $row) {
            $rows[] = ['domain' => (string) $row['domain'], 'row' => $this->mapRow($row)];
        }

        return $rows;
    }

    /**
     * A still-firing suppressed finding must not be silently re-inserted
     * as a fresh row — that would defeat "stop showing."
     *
     * @return array<string, list<string>> ruleId => subjects ('' for domain-wide)
     */
    public function suppressedSubjects(int $domainId): array
    {
        $map = [];

        foreach ($this->fetchByStates($domainId, ['suppressed']) as $row) {
            $map[$row->ruleId][] = $row->subject ?? '';
        }

        return $map;
    }

    public function insert(int $domainId, RuleFinding $finding): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO recommendations (domain_id, rule_id, severity, evidence_json, state)
             VALUES (?, ?, ?, ?, ?)'
        );
        $stmt->execute([$domainId, $finding->ruleId, $finding->severity, $this->encodeEvidence($finding), 'open']);
    }

    /** Refreshes last_seen/evidence without touching state — an acknowledged row stays acknowledged. */
    public function touch(int $id, RuleFinding $finding): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE recommendations SET last_seen = NOW(), severity = ?, evidence_json = ? WHERE id = ?'
        );
        $stmt->execute([$finding->severity, $this->encodeEvidence($finding), $id]);
    }

    /** spec §10.5 auto-resolution — the trigger no longer fires. */
    public function resolve(int $id): void
    {
        $stmt = $this->pdo->prepare("UPDATE recommendations SET state = 'resolved', resolved_at = NOW() WHERE id = ?");
        $stmt->execute([$id]);
    }

    /**
     * @param list<string> $states
     * @return list<ExistingRecommendation>
     */
    private function fetchByStates(int $domainId, array $states): array
    {
        $placeholders = implode(',', array_fill(0, \count($states), '?'));
        $stmt         = $this->pdo->prepare(
            "SELECT id, rule_id, evidence_json FROM recommendations WHERE domain_id = ? AND state IN ($placeholders)"
        );
        $stmt->execute([$domainId, ...$states]);

        $result = [];

        foreach ($stmt as $row) {
            /** @var mixed $evidence */
            $evidence = $row['evidence_json'] !== null ? json_decode((string) $row['evidence_json'], true) : [];
            $subject  = \is_array($evidence) ? ($evidence['_subject'] ?? null) : null;

            $result[] = new ExistingRecommendation(
                (int) $row['id'],
                (string) $row['rule_id'],
                \is_string($subject) ? $subject : null
            );
        }

        return $result;
    }

    private function encodeEvidence(RuleFinding $finding): string
    {
        return json_encode(['_subject' => $finding->subject, ...$finding->evidence], JSON_THROW_ON_ERROR);
    }

    /** @param array<string, mixed> $row */
    private function mapRow(array $row): RecommendationRow
    {
        /** @var mixed $evidence */
        $evidence = $row['evidence_json'] !== null ? json_decode((string) $row['evidence_json'], true) : [];
        $evidence = \is_array($evidence) ? $evidence : [];
        $subject  = $evidence['_subject'] ?? null;
        unset($evidence['_subject']);

        return new RecommendationRow(
            (int) $row['id'],
            (string) $row['rule_id'],
            (string) $row['severity'],
            \is_string($subject) ? $subject : null,
            $evidence,
            (string) $row['first_seen'],
            (string) $row['last_seen'],
            (string) $row['state'],
        );
    }
}
