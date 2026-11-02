<?php

declare(strict_types=1);

namespace App\HealthCheck\Fix;

/**
 * Pure, testable — operates only on the `detail` array DmarcCheck::run()
 * already computed. Missing-rua= reconstructs the existing record from
 * recognized parsed fields rather than clobbering those settings. Never suggests
 * advancing p=none — that's a policy decision backed by report evidence
 * (spec §10.6/R7/R8), not a mechanical DNS fix.
 *
 * A pct= removal fix is offered only when removal cannot increase the
 * requested policy's scope: pct=100 or p=none. Lower enforcement percentages
 * require a deliberate operator decision.
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

        if (isset($detail['pct']) && \is_int($detail['pct'])
                                  && $detail['pct'] >= 0 && $detail['pct'] <= 100
                                  && ($detail['pct'] === 100 || $policy === 'none')
        ) {
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

        if (!empty($detail['non_existent_subdomain_policy']) && \is_string($detail['non_existent_subdomain_policy'])) {
            $parts[] = 'np=' . $detail['non_existent_subdomain_policy'];
        }

        if (!empty($detail['psd']) && \is_string($detail['psd'])) {
            $parts[] = 'psd=' . $detail['psd'];
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

        if (!empty($detail['testing']) && \is_string($detail['testing'])) {
            $parts[] = 't=' . $detail['testing'];
        }

        foreach (['rf', 'ri'] as $tag) {
            if (!empty($detail[$tag]) && \is_string($detail[$tag])) {
                $parts[] = "$tag=" . $detail[$tag];
            }
        }

        if (!empty($detail['fo']) && \is_string($detail['fo'])) {
            $parts[] = 'fo=' . $detail['fo'];
        }

        $parts[] = 'rua=mailto:' . $mailFrom;

        $ruf = $detail['ruf'] ?? [];

        if (\is_array($ruf) && $ruf !== []) {
            $parts[] = 'ruf=mailto:' . implode(',', $ruf);
        }

        return new HealthCheckFix(
            'DNS TXT record at _dmarc.' . $domain,
            '_dmarc.' . $domain,
            'TXT',
            implode('; ', $parts),
            'Your existing record is missing rua=, so reports never reach this tool — this adds the destination while retaining the policy and report tags this check recognizes.',
        );
    }

    /**
     * RFC 9989 (DMARCbis) removed pct= as a defined tag (docs/feature-dmarcbis.md
     * D2/D3) — reconstructs the current record without it, keeping the
     * other recognized tags, including the *existing* rua=
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

        if (!empty($detail['psd']) && \is_string($detail['psd'])) {
            $parts[] = 'psd=' . $detail['psd'];
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

        foreach (['rf', 'ri'] as $tag) {
            if (!empty($detail[$tag]) && \is_string($detail[$tag])) {
                $parts[] = "$tag=" . $detail[$tag];
            }
        }

        if (!empty($detail['fo']) && \is_string($detail['fo'])) {
            $parts[] = 'fo=' . $detail['fo'];
        }

        $rua = $detail['rua'] ?? [];

        if (\is_array($rua) && $rua !== []) {
            $parts[] = 'rua=mailto:' . implode(',', $rua);
        }

        $ruf = $detail['ruf'] ?? [];

        if (\is_array($ruf) && $ruf !== []) {
            $parts[] = 'ruf=mailto:' . implode(',', $ruf);
        }

        return new HealthCheckFix(
            'DNS TXT record at _dmarc.' . $domain,
            '_dmarc.' . $domain,
            'TXT',
            implode('; ', $parts),
            'pct= was removed as a defined tag under RFC 9989 (DMARCbis) — this drops it while retaining the other policy and report tags this check recognizes. Not urgent, a good candidate for your next DNS edit.',
        );
    }
}
