<?php

declare(strict_types=1);

namespace App\Recommendation;

/** A currently open/acknowledged `recommendations` row, as the reconciler needs it. */
final readonly class ExistingRecommendation
{
    public function __construct(
        public int $id,
        public string $ruleId,
        public ?string $subject,
    ) {
    }
}
