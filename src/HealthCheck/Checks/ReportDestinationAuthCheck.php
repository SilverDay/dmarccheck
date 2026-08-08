<?php

declare(strict_types=1);

namespace App\HealthCheck\Checks;

use App\HealthCheck\DmarcRecord;
use App\HealthCheck\DnsResolver;
use App\HealthCheck\HealthCheckItemResult;

/**
 * RFC 7489 §7.1 external report-destination authorization. When a domain's
 * `rua` points to a mailbox on a *different* domain — the exact
 * roya.at-reports-to-a-silverday.de-mailbox scenario from spec §11.2 — the
 * destination domain must publish an authorization record at
 * `<policy-domain>._report._dmarc.<destination-domain>`, or some receivers
 * silently refuse to send reports at all.
 */
final class ReportDestinationAuthCheck implements HealthCheck
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

        $record = $dmarcTxt === [] ? null : DmarcRecord::parse($dmarcTxt[0]);

        if ($record === null) {
            return [new HealthCheckItemResult('dns', 'report_destination_auth', HealthCheckItemResult::INFO, [
                'reason' => 'no valid DMARC record to read rua= from',
            ])];
        }

        $externalDomains = array_values(array_filter(
            $record->ruaDomains(),
            static fn (string $d): bool => $d !== strtolower($domain)
        ));

        if ($externalDomains === []) {
            return [new HealthCheckItemResult('dns', 'report_destination_auth', HealthCheckItemResult::INFO, [
                'reason' => 'no cross-domain rua destinations — nothing to authorize',
            ])];
        }

        $results = [];

        foreach ($externalDomains as $destination) {
            $name       = $domain . '._report._dmarc.' . $destination;
            $answer     = $this->dns->txt($name);
            $authorized = array_filter(
                $answer,
                static fn (string $t): bool => str_starts_with(strtolower(trim($t)), 'v=dmarc1')
            );

            $results[] = new HealthCheckItemResult(
                'dns',
                'report_destination_auth',
                $authorized !== [] ? HealthCheckItemResult::PASS : HealthCheckItemResult::FAIL,
                [
                    'destination_domain' => $destination,
                    'expected_record'    => $name,
                    'reason'             => $authorized !== []
                        ? 'authorization record present'
                        : 'missing authorization record — receivers may silently refuse to send reports',
                ]
            );
        }

        return $results;
    }
}
