<?php

declare(strict_types=1);

namespace App\Ingest;

/**
 * Immutable result of parsing one aggregate report (spec §5).
 */
final readonly class ParsedReport
{
    /**
     * @param list<array<string, mixed>> $records
     * @param list<string>               $warnings  skipped/malformed records
     */
    public function __construct(
        public string $domain,
        public string $reporterOrg,
        public string $reportId,
        public \DateTimeImmutable $dateBegin,
        public \DateTimeImmutable $dateEnd,
        public string $policyPublished,
        public array $records,
        public array $warnings = [],
    ) {
    }

    public function recordCount(): int
    {
        return count($this->records);
    }

    public function messageCount(): int
    {
        return array_sum(array_column($this->records, 'count'));
    }
}
