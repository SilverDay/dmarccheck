<?php

declare(strict_types=1);

namespace App\Tests\Recommendation;

use App\Recommendation\AnalysisContext;
use App\Recommendation\SourceStat;

/** @internal test helper — builds an AnalysisContext with sensible defaults, override just what a test cares about */
final class ContextFactory
{
    /**
     * @param list<SourceStat> $standardStats
     * @param list<SourceStat> $sustainedStats
     */
    public static function make(
        int $domainId = 1,
        string $domain = 'example.com',
        ?string $currentPublishedPolicy = 'p=reject; sp=reject',
        ?string $approvedBaselinePolicy = null,
        string $targetPolicy = 'p=reject; sp=reject',
        bool $nonSending = false,
        array $standardStats = [],
        array $sustainedStats = [],
        ?int $spfLiveLookupCount = 1,
        int $windowDays = 7,
        int $sustainedMinDays = 3,
    ): AnalysisContext {
        return new AnalysisContext(
            $domainId,
            $domain,
            $currentPublishedPolicy,
            $approvedBaselinePolicy,
            $targetPolicy,
            $nonSending,
            $standardStats,
            $sustainedStats,
            $spfLiveLookupCount,
            $windowDays,
            $sustainedMinDays,
        );
    }
}
