<?php

declare(strict_types=1);

namespace App\HealthCheck\Fix;

/**
 * Pure, testable — operates only on the `detail` array DmarcCheck::run()
 * already computed. Missing-rua= reconstructs the existing record from
 * its already-parsed fields rather than clobbering it. Never suggests
 * advancing p=none — that's a policy decision backed by report evidence
 * (spec §10.6/R7/R8), not a mechanical DNS fix.
 */
final class DmarcFixSuggester
{
    /**
     * @param array<string, mixed> $detail DmarcCheck::run()'s HealthCheckItemResult::$detail
     *
     * @return list<HealthCheckFix>
     */
    public static function suggest(string $domain, array $detail, string $mailFrom): array
    {
        $reason = isset($detail['reason']) && \is_string($detail['reason']) ? $detail['reason'] : null;

        if ($reason !== null && str_starts_with($reason, 'no DMARC record found')) {
            return [new HealthCheckFix(
                'DNS TXT record at _dmarc.' . $domain,
                '_dmarc.' . $domain,
                'TXT',
                'v=DMARC1; p=none; rua=mailto:' . $mailFrom,
                'A safe starting point that only monitors — nothing about mail delivery changes.',
            )];
        }

        if ($reason !== null) {
            // Multiple records / invalid or missing p= tag — ambiguous, no generated fix.
            return [];
        }

        $rua = $detail['rua'] ?? [];

        if (!\is_array($rua) || $rua !== []) {
            return [];
        }

        $policy = isset($detail['policy']) && \is_string($detail['policy']) ? $detail['policy'] : null;

        if ($policy === null) {
            return [];
        }

        $parts = ['v=DMARC1', "p=$policy"];

        if (!empty($detail['subdomain_policy']) && \is_string($detail['subdomain_policy'])) {
            $parts[] = 'sp=' . $detail['subdomain_policy'];
        }

        if (isset($detail['pct']) && \is_int($detail['pct'])) {
            $parts[] = 'pct=' . $detail['pct'];
        }

        if (!empty($detail['adkim']) && \is_string($detail['adkim'])) {
            $parts[] = 'adkim=' . $detail['adkim'];
        }

        if (!empty($detail['aspf']) && \is_string($detail['aspf'])) {
            $parts[] = 'aspf=' . $detail['aspf'];
        }

        $parts[] = 'rua=mailto:' . $mailFrom;

        return [new HealthCheckFix(
            'DNS TXT record at _dmarc.' . $domain,
            '_dmarc.' . $domain,
            'TXT',
            implode('; ', $parts),
            'Your existing record is missing rua=, so reports never reach this tool — this is your current record with that added, nothing else changed.',
        )];
    }
}
