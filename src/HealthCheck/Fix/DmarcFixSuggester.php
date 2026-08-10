<?php

declare(strict_types=1);

namespace App\HealthCheck\Fix;

/**
 * Pure, testable — operates only on the `detail` array DmarcCheck::run()
 * already computed. Missing-rua= reconstructs the existing record from
 * its already-parsed fields rather than clobbering it. Never suggests
 * advancing p=none — that's a policy decision backed by report evidence
 * (spec §10.6/R7/R8), not a mechanical DNS fix.
 *
 * Can return more than one fix at once — e.g. a domain missing rua= that
 * also still publishes the RFC 9989 (DMARCbis)-removed pct= tag gets both
 * fixes independently (docs/feature-dmarcbis.md Phase 3).
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

        $policy = isset($detail['policy']) && \is_string($detail['policy']) ? $detail['policy'] : null;

        if ($policy === null) {
            return [];
        }

        $fixes = [];

        $rua = $detail['rua'] ?? [];

        if (\is_array($rua) && $rua === []) {
            $fixes[] = self::missingRuaFix($domain, $detail, $policy, $mailFrom);
        }

        if (isset($detail['pct']) && \is_int($detail['pct'])) {
            $fixes[] = self::dropPctFix($domain, $detail, $policy);
        }

        return $fixes;
    }

    /** @param array<string, mixed> $detail */
    private static function missingRuaFix(string $domain, array $detail, string $policy, string $mailFrom): HealthCheckFix
    {
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

        return new HealthCheckFix(
            'DNS TXT record at _dmarc.' . $domain,
            '_dmarc.' . $domain,
            'TXT',
            implode('; ', $parts),
            'Your existing record is missing rua=, so reports never reach this tool — this is your current record with that added, nothing else changed.',
        );
    }

    /**
     * RFC 9989 (DMARCbis) removed pct= as a defined tag (docs/feature-dmarcbis.md
     * D2/D3) — reconstructs the current record without it, keeping every
     * other tag that's actually set, including the *existing* rua=
     * addresses verbatim (not $mailFrom — this fix isn't about adding
     * reporting, only dropping the removed tag).
     *
     * @param array<string, mixed> $detail
     */
    private static function dropPctFix(string $domain, array $detail, string $policy): HealthCheckFix
    {
        $parts = ['v=DMARC1', "p=$policy"];

        if (!empty($detail['subdomain_policy']) && \is_string($detail['subdomain_policy'])) {
            $parts[] = 'sp=' . $detail['subdomain_policy'];
        }

        if (!empty($detail['non_existent_subdomain_policy']) && \is_string($detail['non_existent_subdomain_policy'])) {
            $parts[] = 'np=' . $detail['non_existent_subdomain_policy'];
        }

        // pct= deliberately omitted — this is the whole point of this fix.

        if (!empty($detail['adkim']) && \is_string($detail['adkim'])) {
            $parts[] = 'adkim=' . $detail['adkim'];
        }

        if (!empty($detail['aspf']) && \is_string($detail['aspf'])) {
            $parts[] = 'aspf=' . $detail['aspf'];
        }

        if (!empty($detail['testing']) && \is_string($detail['testing'])) {
            $parts[] = 't=' . $detail['testing'];
        }

        $rua = $detail['rua'] ?? [];

        if (\is_array($rua) && $rua !== []) {
            $parts[] = 'rua=mailto:' . implode(',', $rua);
        }

        return new HealthCheckFix(
            'DNS TXT record at _dmarc.' . $domain,
            '_dmarc.' . $domain,
            'TXT',
            implode('; ', $parts),
            'pct= was removed as a defined tag under RFC 9989 (DMARCbis) — this is your current record with it dropped, everything else unchanged. Not urgent, a good candidate for your next DNS edit.',
        );
    }
}
