<?php

declare(strict_types=1);

namespace App\Recommendation;

/** A `recommendations` row as the dashboard drill-down (spec §7.2) needs it for display. */
final readonly class RecommendationRow
{
    /** @param array<string, mixed> $evidence */
    public function __construct(
        public int $id,
        public string $ruleId,
        public string $severity,
        public ?string $subject,
        public array $evidence,
        public string $firstSeen,
        public string $lastSeen,
        public string $state,
    ) {
    }
}
