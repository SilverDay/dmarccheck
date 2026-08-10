<?php

declare(strict_types=1);

namespace App\HealthCheck\Fix;

/** Pure, testable — mirrors ReportDestinationAuthCheck::run()'s per-destination detail shape. */
final class ReportDestinationAuthFixSuggester
{
    /**
     * @param array<string, mixed> $detail ReportDestinationAuthCheck::run()'s HealthCheckItemResult::$detail
     *
     * @return list<HealthCheckFix>
     */
    public static function suggest(string $domain, array $detail): array
    {
        $reason = isset($detail['reason']) && \is_string($detail['reason']) ? $detail['reason'] : null;

        if ($reason !== 'missing authorization record — receivers may silently refuse to send reports') {
            return [];
        }

        $destination    = isset($detail['destination_domain']) && \is_string($detail['destination_domain']) ? $detail['destination_domain'] : null;
        $expectedRecord = isset($detail['expected_record'])    && \is_string($detail['expected_record']) ? $detail['expected_record'] : null;

        if ($destination === null || $expectedRecord === null) {
            return [];
        }

        return [new HealthCheckFix(
            'DNS TXT record at ' . $expectedRecord,
            $expectedRecord,
            'TXT',
            'v=DMARC1',
            "Authorizes $destination to receive DMARC aggregate reports on behalf of $domain (RFC 7489 §7.1) — without it, some receivers"
                . ' silently refuse to send reports to this cross-domain rua= destination.',
        )];
    }
}
