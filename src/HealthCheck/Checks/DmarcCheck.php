<?php

declare(strict_types=1);

namespace App\HealthCheck\Checks;

use App\HealthCheck\DmarcRecord;
use App\HealthCheck\DnsResolver;
use App\HealthCheck\HealthCheckItemResult;
use App\HealthCheck\OrgDomain;

final class DmarcCheck implements HealthCheck
{
    private readonly OrgDomain $orgDomain;

    public function __construct(private readonly DnsResolver $dns)
    {
        $this->orgDomain = new OrgDomain($dns);
    }

    public function run(string $domain): array
    {
        $txt      = $this->dns->txt('_dmarc.' . $domain);
        $dmarcTxt = array_values(array_filter(
            $txt,
            static fn (string $t): bool => str_starts_with(strtolower(trim($t)), 'v=dmarc1')
        ));

        if ($dmarcTxt === []) {
            return [$this->noOwnRecordResult($domain)];
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

        // Not a status-escalating issue — a still-valid classic-DMARC
        // record isn't broken by this, it's a modernization note (RFC 9989
        // §2/Appendix A.6 removed pct= as a defined tag; docs/feature-dmarcbis.md Phase 2).
        if ($record->pct !== null) {
            $issues[] = 'pct= is published but was removed as a defined tag under RFC 9989 (DMARCbis) — safe to drop at your next DNS edit, not urgent';
        }

        return [new HealthCheckItemResult('dns', 'dmarc', $status, [
            'policy_string'    => $record->toPolicyString(),
            'policy'           => $record->policy,
            'subdomain_policy' => $record->subdomainPolicy,
            'pct'              => $record->pct,
            'adkim'            => $record->adkim,
            'aspf'             => $record->aspf,
            'rua'              => $record->ruaAddresses,
            // DMARCbis (RFC 9989) additions — not yet surfaced in the UI
            // (docs/feature-dmarcbis.md Phase 2), captured here so that
            // work has data to read.
            'non_existent_subdomain_policy' => $record->nonExistentSubdomainPolicy,
            'psd'                           => $record->psd,
            'testing'                       => $record->testing,
            'issues'                        => $issues,
        ])];
    }

    /**
     * No record at `_dmarc.$domain` itself — per RFC 9989 §4.10, that isn't
     * necessarily "uncovered": an ancestor's record can apply via `sp=`
     * inheritance, which is a normal, fully-valid DMARC deployment pattern
     * (most orgs only publish at the apex), not a problem. Only report FAIL
     * when nothing covers this domain anywhere in the chain; the FAIL
     * reason text is left byte-for-byte identical to before this check
     * existed, since DmarcFixSuggester pattern-matches it to offer its
     * "create a starter record" fix, which must keep firing for genuinely
     * uncovered domains.
     */
    private function noOwnRecordResult(string $domain): HealthCheckItemResult
    {
        $org = $this->orgDomain->resolve($domain);

        if ($org->organizationalDomain === null || $org->record === null) {
            return new HealthCheckItemResult('dns', 'dmarc', HealthCheckItemResult::FAIL, [
                'reason' => 'no DMARC record found at _dmarc.' . $domain,
            ]);
        }

        return new HealthCheckItemResult('dns', 'dmarc', HealthCheckItemResult::INFO, [
            'reason' => sprintf(
                'no DMARC record at _dmarc.%s — inherits policy from organizational domain %s (%s)',
                $domain,
                $org->organizationalDomain,
                $org->record->toPolicyString(),
            ),
            'org_domain'                  => $org->organizationalDomain,
            'org_domain_policy_string'    => $org->record->toPolicyString(),
            'org_domain_discovery_method' => $org->discoveryMethod,
        ]);
    }
}
