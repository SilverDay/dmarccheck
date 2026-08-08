<?php

declare(strict_types=1);

namespace App\Recommendation;

/**
 * Pure diff between this run's findings and the previously open/
 * acknowledged rows (spec §10.5): matches on (ruleId, subject) — subject
 * is the source IP for per-sender rules, `''` (empty string) as the
 * sentinel for domain-wide rules (RuleFinding::$subject is null there).
 * A match refreshes the row (`toTouch`); a finding with no match is new
 * (`toInsert`); an existing row with no matching finding this run means
 * the trigger no longer fires — auto-resolve (`toResolve`).
 *
 * Suppressed rows are handled entirely by the caller: they must not
 * appear in $existing (so they're never auto-resolved — "stop showing"
 * should stick) and their subjects are passed in $suppressedSubjects so a
 * still-firing suppressed finding doesn't get silently re-inserted as a
 * fresh row, which would defeat suppression.
 */
final class RecommendationReconciler
{
    /**
     * @param list<RuleFinding> $findings
     * @param list<ExistingRecommendation> $existing
     * @param array<string, list<string>> $suppressedSubjects ruleId => subjects (or [''] for a suppressed domain-wide rule)
     */
    public function plan(array $findings, array $existing, array $suppressedSubjects): ReconciliationPlan
    {
        $existingByKey = [];

        foreach ($existing as $row) {
            $existingByKey[$this->key($row->ruleId, $row->subject)] = $row;
        }

        $toInsert    = [];
        $toTouch     = [];
        $matchedKeys = [];

        foreach ($findings as $finding) {
            if ($this->isSuppressed($finding, $suppressedSubjects)) {
                continue;
            }

            $key = $this->key($finding->ruleId, $finding->subject);

            if (isset($existingByKey[$key])) {
                $toTouch[]         = ['id' => $existingByKey[$key]->id, 'finding' => $finding];
                $matchedKeys[$key] = true;
            } else {
                $toInsert[] = $finding;
            }
        }

        $toResolve = [];

        foreach ($existing as $row) {
            if (!isset($matchedKeys[$this->key($row->ruleId, $row->subject)])) {
                $toResolve[] = $row->id;
            }
        }

        return new ReconciliationPlan($toInsert, $toTouch, $toResolve);
    }

    private function key(string $ruleId, ?string $subject): string
    {
        return $ruleId . '|' . ($subject ?? '');
    }

    /** @param array<string, list<string>> $suppressedSubjects */
    private function isSuppressed(RuleFinding $finding, array $suppressedSubjects): bool
    {
        $subjects = $suppressedSubjects[$finding->ruleId] ?? [];

        return \in_array($finding->subject ?? '', $subjects, true);
    }
}
