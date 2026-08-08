<?php

declare(strict_types=1);

namespace App\HealthCheck\Checks;

use App\HealthCheck\DnsResolver;
use App\HealthCheck\HealthCheckItemResult;

/**
 * spec §11.2 SPF. Counts top-level DNS-lookup mechanisms
 * (include/a/mx/ptr/exists + the redirect modifier) only — not a full
 * recursive RFC 7208 evaluator (an `include:` can itself contain further
 * lookup mechanisms; a fully correct count means resolving the whole
 * chain). This is a reasonable approximation, not an RFC 7208-compliance
 * certification — stated directly per spec §11.4's own "state limitations
 * clearly" principle rather than silently overclaiming precision.
 */
final class SpfCheck implements HealthCheck
{
    private const int MAX_LOOKUPS         = 10;
    private const array LOOKUP_MECHANISMS = ['include', 'a', 'mx', 'ptr', 'exists', 'redirect'];

    public function __construct(private readonly DnsResolver $dns)
    {
    }

    public function run(string $domain): array
    {
        $txt        = $this->dns->txt($domain);
        $spfRecords = array_values(array_filter(
            $txt,
            static fn (string $t): bool => str_starts_with(strtolower(trim($t)), 'v=spf1')
        ));

        if ($spfRecords === []) {
            return [new HealthCheckItemResult('dns', 'spf', HealthCheckItemResult::FAIL, [
                'reason' => 'no SPF record found',
            ])];
        }

        if (\count($spfRecords) > 1) {
            return [new HealthCheckItemResult('dns', 'spf', HealthCheckItemResult::FAIL, [
                'reason'  => 'multiple SPF records published (RFC 7208 permerror)',
                'records' => $spfRecords,
            ])];
        }

        $record                       = $spfRecords[0];
        [$lookupCount, $allQualifier] = $this->analyze($record);

        $issues = [];
        $status = HealthCheckItemResult::PASS;

        if ($lookupCount > self::MAX_LOOKUPS) {
            $issues[] = "DNS-lookup mechanisms ($lookupCount) exceed the RFC 7208 limit of " . self::MAX_LOOKUPS . ' (permerror)';
            $status   = HealthCheckItemResult::FAIL;
        }

        $status = match ($allQualifier) {
            '+'      => HealthCheckItemResult::FAIL,
            '~', '?' => $status === HealthCheckItemResult::FAIL ? $status : HealthCheckItemResult::WARN,
            default  => $status,
        };

        if ($allQualifier === '+') {
            $issues[] = "'+all' publishes an open, unrestricted SPF result — treat as a critical misconfiguration";
        } elseif ($allQualifier === '~' || $allQualifier === '?') {
            $issues[] = "'{$allQualifier}all' is a weak/neutral catch-all qualifier";
        } elseif ($allQualifier === null && $status === HealthCheckItemResult::PASS) {
            $issues[] = "no 'all' mechanism — non-matching senders get an implicit neutral result";
            $status   = HealthCheckItemResult::WARN;
        }

        return [new HealthCheckItemResult('dns', 'spf', $status, [
            'record'       => $record,
            'lookup_count' => $lookupCount,
            'issues'       => $issues,
        ])];
    }

    /** @return array{0: int, 1: string|null} [lookupCount, allQualifier] */
    private function analyze(string $record): array
    {
        $tokens       = preg_split('/\s+/', trim($record)) ?: [];
        $lookupCount  = 0;
        $allQualifier = null;

        foreach ($tokens as $token) {
            if ($token === '' || strtolower($token) === 'v=spf1') {
                continue;
            }

            $qualifier = '+';

            if (\in_array($token[0], ['+', '-', '~', '?'], true)) {
                $qualifier = $token[0];
                $token     = substr($token, 1);
            }

            preg_match('/^[a-zA-Z0-9]+/', $token, $matches);
            $name = strtolower($matches[0] ?? '');

            if (\in_array($name, self::LOOKUP_MECHANISMS, true)) {
                $lookupCount++;
            }

            if ($name === 'all') {
                $allQualifier = $qualifier;
            }
        }

        return [$lookupCount, $allQualifier];
    }
}
