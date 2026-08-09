<?php

declare(strict_types=1);

namespace App\HealthCheck\Fix;

/**
 * Pure, testable — operates only on the `detail` array SpfCheck::run()
 * already computed and stored, no new DNS calls. Deliberately narrow:
 * only rewrites what's mechanically unambiguous (missing record, +all,
 * no all mechanism at all). Multiple records and the lookup-limit case
 * are left to the existing reason text + help article — there's no safe
 * way to guess which of several records to keep, or which `include:`
 * mechanisms are safe to drop.
 */
final class SpfFixSuggester
{
    /**
     * @param array<string, mixed> $detail SpfCheck::run()'s HealthCheckItemResult::$detail
     *
     * @return list<HealthCheckFix>
     */
    public static function suggest(string $domain, array $detail): array
    {
        $reason = isset($detail['reason']) && \is_string($detail['reason']) ? $detail['reason'] : null;

        if ($reason === 'no SPF record found') {
            return [new HealthCheckFix(
                'DNS TXT record at ' . $domain,
                $domain,
                'TXT',
                'v=spf1 mx -all',
                'Minimal starting point: authorizes whatever your MX record points to and hard-fails everything else. Add an include: for each third-party sender.',
            )];
        }

        if (!isset($detail['record']) || !\is_string($detail['record'])) {
            return [];
        }

        $record    = $detail['record'];
        $qualifier = self::allQualifier($record);

        if ($qualifier === '+') {
            return [new HealthCheckFix(
                'DNS TXT record at ' . $domain,
                $domain,
                'TXT',
                self::withAllQualifier($record, '-'),
                'Your record\'s +all lets anyone pass SPF as your domain — this is the same record with only the all mechanism corrected to -all.',
            )];
        }

        if ($qualifier === null) {
            return [new HealthCheckFix(
                'DNS TXT record at ' . $domain,
                $domain,
                'TXT',
                self::withAllQualifier($record, '~'),
                'Your record has no all mechanism, so non-matching senders get an implicit neutral result — this adds a conservative ~all (softfail). Switch to -all once you\'ve confirmed no legitimate sender is missing.',
            )];
        }

        // ~all / ?all already set, or -all already correct — a deliberate
        // transition state or already fine, not a mechanical fix either way.
        return [];
    }

    /** Returns the qualifier character ('+', '-', '~', '?') of the record's `all` mechanism, or null if absent. */
    private static function allQualifier(string $record): ?string
    {
        foreach (self::tokens($record) as $token) {
            if (strtolower($token['name']) === 'all') {
                return $token['qualifier'];
            }
        }

        return null;
    }

    /** Rewrites (or appends, if absent) the `all` mechanism with the given qualifier, leaving every other token untouched. */
    private static function withAllQualifier(string $record, string $qualifier): string
    {
        $kept = array_filter(
            self::tokens($record),
            static fn (array $token): bool => strtolower($token['name']) !== 'all'
        );

        $parts   = ['v=spf1', ...array_map(static fn (array $token): string => $token['raw'], $kept)];
        $parts[] = $qualifier . 'all';

        return implode(' ', $parts);
    }

    /** @return list<array{raw: string, qualifier: string, name: string}> */
    private static function tokens(string $record): array
    {
        $tokens = preg_split('/\s+/', trim($record)) ?: [];
        $result = [];

        foreach ($tokens as $token) {
            if ($token === '' || strtolower($token) === 'v=spf1') {
                continue;
            }

            $qualifier = '+';
            $rest      = $token;

            if (\in_array($token[0], ['+', '-', '~', '?'], true)) {
                $qualifier = $token[0];
                $rest      = substr($token, 1);
            }

            preg_match('/^[a-zA-Z0-9]+/', $rest, $matches);

            $result[] = ['raw' => $token, 'qualifier' => $qualifier, 'name' => $matches[0] ?? ''];
        }

        return $result;
    }
}
