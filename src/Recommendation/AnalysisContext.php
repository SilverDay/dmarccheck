<?php

declare(strict_types=1);

namespace App\Recommendation;

/** Everything a Rule needs to evaluate one domain for one run. */
final readonly class AnalysisContext
{
    /**
     * @param list<SourceStat> $standardWindowStats
     * @param list<SourceStat> $sustainedWindowStats
     */
    public function __construct(
        public int $domainId,
        public string $domain,
        public ?string $currentPublishedPolicy,
        public ?string $approvedBaselinePolicy,
        public string $targetPolicy,
        public bool $nonSending,
        public array $standardWindowStats,
        public array $sustainedWindowStats,
        public ?int $spfLiveLookupCount,
        public int $windowDays,
        public int $sustainedMinDays,
    ) {
    }
}
