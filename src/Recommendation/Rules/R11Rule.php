<?php

declare(strict_types=1);

namespace App\Recommendation\Rules;

use App\Recommendation\AnalysisContext;
use App\Recommendation\PolicyLevel;
use App\Recommendation\RuleFinding;

/** spec §10.3 R11: `sp` unset while subdomain spoofing is observed. Medium severity. */
final class R11Rule implements Rule
{
    public function evaluate(AnalysisContext $context): array
    {
        if (PolicyLevel::extractSubdomainPolicy($context->currentPublishedPolicy) !== null) {
            return [];
        }

        $offending = [];

        foreach ($context->standardWindowStats as $stat) {
            if (!$stat->hasTotalFailure()) {
                continue;
            }

            foreach ($stat->headerFromDomains as $headerFrom) {
                if ($this->isStrictSubdomain($headerFrom, $context->domain)) {
                    $offending[$headerFrom] = true;
                }
            }
        }

        if ($offending === []) {
            return [];
        }

        return [new RuleFinding('R11', 'medium', null, [
            'subdomains'  => array_keys($offending),
            'window_days' => $context->windowDays,
        ])];
    }

    private function isStrictSubdomain(string $headerFrom, string $domain): bool
    {
        $headerFrom = strtolower($headerFrom);
        $domain     = strtolower($domain);

        return $headerFrom !== $domain && str_ends_with($headerFrom, '.' . $domain);
    }
}
