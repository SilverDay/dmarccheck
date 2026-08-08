<?php

declare(strict_types=1);

namespace App\HealthCheck\Checks;

use App\HealthCheck\DmarcRecord;
use App\HealthCheck\DnsResolver;
use App\HealthCheck\HealthCheckItemResult;

final class DmarcCheck implements HealthCheck
{
    public function __construct(private readonly DnsResolver $dns)
    {
    }

    public function run(string $domain): array
    {
        $txt      = $this->dns->txt('_dmarc.' . $domain);
        $dmarcTxt = array_values(array_filter(
            $txt,
            static fn (string $t): bool => str_starts_with(strtolower(trim($t)), 'v=dmarc1')
        ));

        if ($dmarcTxt === []) {
            return [new HealthCheckItemResult('dns', 'dmarc', HealthCheckItemResult::FAIL, [
                'reason' => 'no DMARC record found at _dmarc.' . $domain,
            ])];
        }

        if (\count($dmarcTxt) > 1) {
            return [new HealthCheckItemResult('dns', 'dmarc', HealthCheckItemResult::FAIL, [
                'reason'  => 'multiple DMARC records published',
                'records' => $dmarcTxt,
            ])];
        }

        $record = DmarcRecord::parse($dmarcTxt[0]);

        if ($record === null || !\in_array($record->policy, ['none', 'quarantine', 'reject'], true)) {
            return [new HealthCheckItemResult('dns', 'dmarc', HealthCheckItemResult::FAIL, [
                'reason' => 'invalid or missing p= policy tag',
                'raw'    => $dmarcTxt[0],
            ])];
        }

        $issues = [];
        $status = HealthCheckItemResult::PASS;

        if ($record->ruaAddresses === []) {
            $issues[] = 'no rua= aggregate report destination — reports cannot reach this tool';
            $status   = HealthCheckItemResult::WARN;
        }

        if ($record->policy === 'none') {
            $issues[] = "policy is 'none' — monitoring only, not enforcing";
            $status   = HealthCheckItemResult::WARN;
        }

        return [new HealthCheckItemResult('dns', 'dmarc', $status, [
            'policy_string'    => $record->toPolicyString(),
            'policy'           => $record->policy,
            'subdomain_policy' => $record->subdomainPolicy,
            'pct'              => $record->pct,
            'adkim'            => $record->adkim,
            'aspf'             => $record->aspf,
            'rua'              => $record->ruaAddresses,
            'issues'           => $issues,
        ])];
    }
}
