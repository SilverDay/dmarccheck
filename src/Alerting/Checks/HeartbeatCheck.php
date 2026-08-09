<?php

declare(strict_types=1);

namespace App\Alerting\Checks;

use App\Alerting\AlertContext;
use App\Alerting\AlertFinding;
use DateTimeImmutable;

/**
 * spec §8 dead-man's-switch: no reports ingested for a domain in N days.
 * Catches a broken ingestion pipeline (IMAP poll down, mailbox full) or a
 * tampered/removed `rua` DNS record — both are silent otherwise, since the
 * symptom is *absence* of data. For a domain with zero reports ever, falls
 * back to `domainCreatedAt` so a brand-new onboarding doesn't fire on day one.
 */
final class HeartbeatCheck implements AlertCheck
{
    public function __construct(private readonly int $heartbeatDays)
    {
    }

    public function evaluate(AlertContext $context): array
    {
        $reference = $context->lastReportReceivedAt ?? $context->domainCreatedAt;
        $cutoff    = (new DateTimeImmutable())->modify("-{$this->heartbeatDays} days");

        if ($reference >= $cutoff) {
            return [];
        }

        return [new AlertFinding(
            'heartbeat',
            $context->domain,
            \sprintf(
                'No DMARC reports received for %s since %s (heartbeat threshold: %d day(s)).',
                $context->domain,
                $reference->format('Y-m-d'),
                $this->heartbeatDays,
            ),
            [
                'last_report_received_at' => $context->lastReportReceivedAt?->format('Y-m-d H:i:s'),
                'domain_created_at'       => $context->domainCreatedAt->format('Y-m-d H:i:s'),
                'heartbeat_days'          => $this->heartbeatDays,
            ],
        )];
    }
}
