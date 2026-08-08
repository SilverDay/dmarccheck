<?php

declare(strict_types=1);

namespace App\Recommendation;

/**
 * One rule firing. `subject` is the reconciliation identity key within a
 * (domain, rule) pair: the source IP for per-sender rules (R1/R2/R3/R12),
 * `null` for domain-wide rules (R4-R11, each naturally singular per domain).
 */
final readonly class RuleFinding
{
    /** @param array<string, mixed> $evidence */
    public function __construct(
        public string $ruleId,
        public string $severity,
        public ?string $subject,
        public array $evidence,
    ) {
    }
}
