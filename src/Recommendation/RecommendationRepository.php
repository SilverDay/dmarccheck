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
}
