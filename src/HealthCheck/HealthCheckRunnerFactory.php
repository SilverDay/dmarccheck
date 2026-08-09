<?php

declare(strict_types=1);

namespace App\HealthCheck;

use App\Config;
use App\Enrichment\SystemRdnsResolver;
use App\HealthCheck\Checks\BimiCheck;
use App\HealthCheck\Checks\DkimCheck;
use App\HealthCheck\Checks\DmarcCheck;
use App\HealthCheck\Checks\DnsblCheck;
use App\HealthCheck\Checks\DnssecCheck;
use App\HealthCheck\Checks\HealthCheck;
use App\HealthCheck\Checks\MtaStsCheck;
use App\HealthCheck\Checks\MxCheck;
use App\HealthCheck\Checks\RdnsFcrdnsCheck;
use App\HealthCheck\Checks\ReportDestinationAuthCheck;
use App\HealthCheck\Checks\SpfCheck;
use App\HealthCheck\Checks\StartTlsCheck;
use App\HealthCheck\Checks\TlsRptCheck;

/**
 * Wires up the §11.2 check list + HealthCheckRunner — extracted from
 * bin/healthcheck.php so this construction lives in exactly one place, now
 * that it's needed from two independent call sites (that CLI script and
 * DomainController::add()'s onboarding health check). DKIM selectors are
 * domain-specific (configured list + selectors already observed in that
 * domain's reports), so the check list is rebuilt per domain via
 * forDomain() rather than built once.
 */
final class HealthCheckRunnerFactory
{
    private readonly DnsResolver $dns;
    private readonly DigLookup $dig;
    private readonly SystemRdnsResolver $rdns;

    /** @var array<string, string> */
    private readonly array $dnsblZones;

    /** @var list<string> */
    private readonly array $configuredSelectors;
    private readonly string $dqsKey;
    private readonly int $smtpTimeout;
    private readonly int $httpTimeout;

    public function __construct(
        Config $config,
        private readonly HealthCheckRepository $repository,
    ) {
        $this->dns = new SystemDnsResolver();
        $this->dig = new SystemDigLookup(
            (string) $config->get('healthcheck.resolver', '127.0.0.1'),
            (int) $config->get('healthcheck.dig_timeout_seconds', 5)
        );
        $this->rdns = new SystemRdnsResolver();

        /** @var array<string, string> $dnsblZones */
        $dnsblZones       = $config->get('healthcheck.dnsbl_zones', []);
        $this->dnsblZones = $dnsblZones;

        /** @var list<string> $configuredSelectors */
        $configuredSelectors       = $config->get('healthcheck.dkim_selectors', []);
        $this->configuredSelectors = $configuredSelectors;

        $this->dqsKey      = (string) $config->get('healthcheck.spamhaus_dqs_key', '');
        $this->smtpTimeout = (int) $config->get('healthcheck.smtp_timeout_seconds', 5);
        $this->httpTimeout = (int) $config->get('healthcheck.http_timeout_seconds', 5);
    }

    public function forDomain(int $domainId): HealthCheckRunner
    {
        $selectors = self::mergeSelectors($this->configuredSelectors, $this->repository->observedDkimSelectors($domainId));

        /** @var list<HealthCheck> $checks */
        $checks = [
            new SpfCheck($this->dns),
            new DmarcCheck($this->dns),
            new ReportDestinationAuthCheck($this->dns),
            new DkimCheck($this->dns, $selectors),
            new MxCheck($this->dns),
            new DnssecCheck($this->dig),
            new MtaStsCheck($this->dns, $this->httpTimeout),
            new TlsRptCheck($this->dns),
            new BimiCheck($this->dns),
            new StartTlsCheck($this->dns, $this->smtpTimeout),
            new DnsblCheck($this->dns, $this->dig, $this->dqsKey, $this->dnsblZones),
            new RdnsFcrdnsCheck($this->dns, $this->rdns),
        ];

        return new HealthCheckRunner($checks, $this->repository);
    }

    /**
     * DKIM selectors to probe are the union of the configured list
     * (`config('healthcheck.dkim_selectors')`) and whatever's already been
     * observed in that domain's reports — deduped, since either source can
     * repeat the other.
     *
     * @param list<string> $configured
     * @param list<string> $observed
     *
     * @return list<string>
     */
    public static function mergeSelectors(array $configured, array $observed): array
    {
        return array_values(array_unique([...$configured, ...$observed]));
    }
}
