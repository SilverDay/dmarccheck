<?php

declare(strict_types=1);

namespace App\Tests\Alerting;

use App\Alerting\AlertContext;
use App\Alerting\UnknownIpVolume;
use DateTimeImmutable;

/** @internal test helper — builds an AlertContext with sensible defaults, override just what a test cares about */
final class ContextFactory
{
    /** @param list<UnknownIpVolume> $unknownIpVolumes */
    public static function make(
        int $domainId = 1,
        string $domain = 'example.com',
        ?DateTimeImmutable $domainCreatedAt = null,
        ?DateTimeImmutable $lastReportReceivedAt = new DateTimeImmutable(),
        ?string $currentPublishedPolicy = 'p=reject; sp=reject',
        ?string $approvedBaselinePolicy = null,
        array $unknownIpVolumes = [],
        int $recentTotalCount = 100,
        ?float $recentPassRatePct = 99.0,
        int $baselineTotalCount = 3000,
        ?float $baselinePassRatePct = 99.0,
    ): AlertContext {
        return new AlertContext(
            $domainId,
            $domain,
            $domainCreatedAt ?? new DateTimeImmutable('-1 year'),
            $lastReportReceivedAt,
            $currentPublishedPolicy,
            $approvedBaselinePolicy,
            $unknownIpVolumes,
            $recentTotalCount,
            $recentPassRatePct,
            $baselineTotalCount,
            $baselinePassRatePct,
        );
    }
}
