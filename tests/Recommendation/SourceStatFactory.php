<?php

declare(strict_types=1);

namespace App\Tests\Recommendation;

use App\Recommendation\SourceStat;

/** @internal test helper */
final class SourceStatFactory
{
    /** @param list<string> $headerFromDomains */
    public static function make(
        string $ip = '203.0.113.5',
        int $totalCount = 10,
        int $passCount = 0,
        int $bothFailedCount = 0,
        int $spfOnlyFailCount = 0,
        int $dkimOnlyFailCount = 0,
        bool $spfAlignmentIssue = false,
        bool $dkimAlignmentIssue = false,
        array $headerFromDomains = [],
        int $distinctReportDays = 1,
        ?string $knownLabel = null,
    ): SourceStat {
        return new SourceStat(
            $ip,
            $totalCount,
            $passCount,
            $bothFailedCount,
            $spfOnlyFailCount,
            $dkimOnlyFailCount,
            $spfAlignmentIssue,
            $dkimAlignmentIssue,
            $headerFromDomains,
            $distinctReportDays,
            $knownLabel,
        );
    }
}
