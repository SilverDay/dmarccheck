<?php

declare(strict_types=1);

namespace App\Alerting;

use DateTimeImmutable;

/** Everything an AlertCheck needs to evaluate one domain for one run (spec §8). */
final readonly class AlertContext
{
    /** @param list<UnknownIpVolume> $unknownIpVolumes */
    public function __construct(
        public int $domainId,
        public string $domain,
        public DateTimeImmutable $domainCreatedAt,
        public ?DateTimeImmutable $lastReportReceivedAt,
        public ?string $currentPublishedPolicy,
        public ?string $approvedBaselinePolicy,
        public array $unknownIpVolumes,
        public int $recentTotalCount,
        public ?float $recentPassRatePct,
        public int $baselineTotalCount,
        public ?float $baselinePassRatePct,
    ) {
    }
}
