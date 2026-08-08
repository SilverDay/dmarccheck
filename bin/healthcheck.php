<?php

declare(strict_types=1);

/**
 * bin/healthcheck.php — spec §11. Point-in-time DNS/network posture check,
 * independent of report data. Run manually, on a schedule, or (in a future
 * admin UI) at domain onboarding:
 *
 *   php bin/healthcheck.php                        # every active domain, trigger=manual
 *   php bin/healthcheck.php example.com             # one domain, trigger=manual
 *   php bin/healthcheck.php example.com --trigger=scheduled
 *
 * 0   17 * * 0  php /srv/dmarc/bin/healthcheck.php --trigger=scheduled >> /var/log/dmarc-healthcheck.log 2>&1
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use App\Config;
use App\Database;
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
use App\HealthCheck\HealthCheckItemResult;
use App\HealthCheck\HealthCheckRepository;
use App\HealthCheck\HealthCheckRunner;
use App\HealthCheck\SystemDigLookup;
use App\HealthCheck\SystemDnsResolver;

$config = Config::load();
$pdo    = Database::connect($config);

$trigger   = 'manual';
$domainArg = null;

foreach (array_slice($argv, 1) as $arg) {
    if (str_starts_with($arg, '--trigger=')) {
        $trigger = substr($arg, \strlen('--trigger='));
    } elseif (!str_starts_with($arg, '--')) {
        $domainArg = $arg;
    }
}

if (!\in_array($trigger, ['manual', 'scheduled'], true)) {
    fwrite(STDERR, "FATAL: --trigger must be 'manual' or 'scheduled'\n");
    exit(1);
}

$dns = new SystemDnsResolver();
$dig = new SystemDigLookup(
    (string) $config->get('healthcheck.resolver', '127.0.0.1'),
    (int) $config->get('healthcheck.dig_timeout_seconds', 5)
);
$rdns       = new SystemRdnsResolver();
$repository = new HealthCheckRepository($pdo);

/** @var array<string, string> $dnsblZones */
$dnsblZones = $config->get('healthcheck.dnsbl_zones', []);
/** @var list<string> $configuredSelectors */
$configuredSelectors = $config->get('healthcheck.dkim_selectors', []);
$dqsKey              = (string) $config->get('healthcheck.spamhaus_dqs_key', '');
$smtpTimeout         = (int) $config->get('healthcheck.smtp_timeout_seconds', 5);
$httpTimeout         = (int) $config->get('healthcheck.http_timeout_seconds', 5);

if ($domainArg !== null) {
    $stmt = $pdo->prepare('SELECT id, domain FROM domains WHERE domain = ? AND active = 1');
    $stmt->execute([strtolower($domainArg)]);
} else {
    $stmt = $pdo->query('SELECT id, domain FROM domains WHERE active = 1 ORDER BY domain');
}

$domains = $stmt->fetchAll();

if ($domains === []) {
    fwrite(STDERR, "No matching active domain(s) found.\n");
    exit(1);
}

foreach ($domains as $row) {
    $domainId = (int) $row['id'];
    $domain   = (string) $row['domain'];

    $selectors = array_values(array_unique([
        ...$configuredSelectors,
        ...$repository->observedDkimSelectors($domainId),
    ]));

    /** @var list<HealthCheck> $checks */
    $checks = [
        new SpfCheck($dns),
        new DmarcCheck($dns),
        new ReportDestinationAuthCheck($dns),
        new DkimCheck($dns, $selectors),
        new MxCheck($dns),
        new DnssecCheck($dig),
        new MtaStsCheck($dns, $httpTimeout),
        new TlsRptCheck($dns),
        new BimiCheck($dns),
        new StartTlsCheck($dns, $smtpTimeout),
        new DnsblCheck($dns, $dig, $dqsKey, $dnsblZones),
        new RdnsFcrdnsCheck($dns, $rdns),
    ];

    $runner = new HealthCheckRunner($checks, $repository);

    try {
        $items = $runner->run($domainId, $domain, $trigger);
    } catch (Throwable $e) {
        fwrite(STDERR, "[fail] $domain: " . $e->getMessage() . "\n");
        continue;
    }

    $tally = ['pass' => 0, 'warn' => 0, 'fail' => 0, 'info' => 0, 'error' => 0];

    foreach ($items as $item) {
        $tally[$item->status] = ($tally[$item->status] ?? 0) + 1;
    }

    printf(
        "[ok] %s — %d pass, %d warn, %d fail, %d info, %d error\n",
        $domain,
        $tally['pass'],
        $tally['warn'],
        $tally['fail'],
        $tally['info'],
        $tally['error']
    );

    foreach ($items as $item) {
        if ($item->status === HealthCheckItemResult::FAIL || $item->status === HealthCheckItemResult::ERROR) {
            fwrite(STDERR, "  [{$item->status}] {$item->category}/{$item->checkName}: " . json_encode($item->detail) . "\n");
        }
    }
}

exit(0);
