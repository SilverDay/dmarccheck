<?php

declare(strict_types=1);

namespace App\Recommendation\Rules;

use App\Recommendation\AnalysisContext;
use App\Recommendation\RuleFinding;

/**
 * spec §10.3 R4: SPF record resolves >10 DNS lookups (RFC 7208 permerror
 * risk). Domain-wide — `spfLiveLookupCount` comes from a live lookup at
 * analysis time (App\HealthCheck\Checks\SpfCheck, reused rather than
 * re-implemented). Medium severity.
 */
final class R4Rule implements Rule
{
    private const int MAX_LOOKUPS = 10;

    public function evaluate(AnalysisContext $context): array
    {
        if ($context->spfLiveLookupCount === null || $context->spfLiveLookupCount <= self::MAX_LOOKUPS) {
            return [];
        }

        return [new RuleFinding('R4', 'medium', null, [
            'lookup_count' => $context->spfLiveLookupCount,
            'limit'        => self::MAX_LOOKUPS,
        ])];
    }
}
