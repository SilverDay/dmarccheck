<?php

declare(strict_types=1);

namespace App\HealthCheck\Checks;

use App\HealthCheck\DnsResolver;
use App\HealthCheck\HealthCheckItemResult;

/**
 * spec §11.2/§11.4: DKIM selectors cannot be enumerated from DNS — this
 * can only probe a caller-supplied list (config's known selectors plus
 * ones already observed in this domain's reports, merged by whoever
 * constructs this check) and report which of *those* resolve to a valid
 * key. A selector missing from the probe list, or the probe list coming
 * up empty, is never "DKIM is absent" — stated in the result, not just a
 * code comment, so it can't be misread in the UI later.
 */
final class DkimCheck implements HealthCheck
{
    /** @param list<string> $selectors */
    public function __construct(
        private readonly DnsResolver $dns,
        private readonly array $selectors,
    ) {
    }

    public function run(string $domain): array
    {
        $results = [];

        foreach (array_unique($this->selectors) as $selector) {
            $item = $this->probe($domain, $selector);

            if ($item !== null) {
                $results[] = $item;
            }
        }

        if ($results === []) {
            return [new HealthCheckItemResult('dns', 'dkim', HealthCheckItemResult::INFO, [
                'reason' => 'none of the probed selectors resolved — DKIM selectors are not enumerable from '
                    . 'DNS alone, so this is not evidence that DKIM is absent',
                'selectors_probed' => array_values(array_unique($this->selectors)),
            ])];
        }

        return $results;
    }

    private function probe(string $domain, string $selector): ?HealthCheckItemResult
    {
        $txt = $this->dns->txt($selector . '._domainkey.' . $domain);

        if ($txt === []) {
            return null;
        }

        $combined  = implode(' ', $txt);
        $publicKey = preg_match('/p=([^;\s]*)/', $combined, $matches) === 1 ? trim($matches[1]) : null;

        [$status, $reason] = match (true) {
            $publicKey === null => [HealthCheckItemResult::WARN, 'record present but no p= tag found'],
            $publicKey === ''   => [HealthCheckItemResult::FAIL, 'empty p= tag — key revoked'],
            default             => [HealthCheckItemResult::PASS, 'valid key published'],
        };

        return new HealthCheckItemResult('dns', 'dkim', $status, [
            'selector' => $selector,
            'reason'   => $reason,
        ]);
    }
}
