<?php

declare(strict_types=1);

namespace App\Recommendation;

/**
 * Per-source-IP aggregate for one domain over one analysis window.
 *
 * `report_records.dkim_result`/`spf_result` are the DMARC-*aligned*
 * verdict (from `<policy_evaluated>`); `spfAlignmentIssue`/
 * `dkimAlignmentIssue` capture the separate signal that the *raw*
 * mechanism (from `auth_results`, pre-alignment) actually passed for at
 * least one of this IP's failing records — that's an alignment-mode
 * problem (R3), not a genuine auth failure (R1/R2).
 */
final readonly class SourceStat
{
    /** @param list<string> $headerFromDomains */
    public function __construct(
        public string $ip,
        public int $totalCount,
        public int $passCount,
        public int $bothFailedCount,
        public int $spfOnlyFailCount,
        public int $dkimOnlyFailCount,
        public bool $spfAlignmentIssue,
        public bool $dkimAlignmentIssue,
        public array $headerFromDomains,
        public int $distinctReportDays,
        public ?string $knownLabel,
    ) {
    }

    public function isKnown(): bool
    {
        return $this->knownLabel !== null;
    }

    /** Convention: a known_senders label containing "forward" marks a known forwarder (see R12). */
    public function isKnownForwarder(): bool
    {
        return $this->knownLabel !== null && stripos($this->knownLabel, 'forward') !== false;
    }

    public function hasTotalFailure(): bool
    {
        return $this->bothFailedCount > 0;
    }

    /**
     * Used by R7/R8: is there any known-sender total failure in this
     * window? Only unknown-source failures are "expected fallout" from
     * tightening policy — a known sender failing means tightening now
     * would actually break something.
     *
     * @param list<self> $stats
     */
    public static function anyKnownTotalFailure(array $stats): bool
    {
        foreach ($stats as $stat) {
            if ($stat->isKnown() && $stat->hasTotalFailure()) {
                return true;
            }
        }

        return false;
    }
}
