<?php

declare(strict_types=1);

namespace App\Recommendation;

final readonly class ReconciliationPlan
{
    /**
     * @param list<RuleFinding> $toInsert
     * @param list<array{id: int, finding: RuleFinding}> $toTouch
     * @param list<int> $toResolve
     */
    public function __construct(
        public array $toInsert,
        public array $toTouch,
        public array $toResolve,
    ) {
    }
}
