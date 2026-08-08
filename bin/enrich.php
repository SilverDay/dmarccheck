<?php

declare(strict_types=1);

/**
 * bin/enrich.php — spec §6. Run from cron, decoupled from ingestion so a
 * slow DNS/ASN lookup never blocks report parsing:
 *
 *   17,47 * * * *  php /srv/dmarc/bin/enrich.php >> /var/log/dmarc-enrich.log 2>&1
 *
 * Reverse DNS + local GeoLite2 ASN lookup + known_senders CIDR matching,
 * writing rdns/asn/asn_org/label/lookup_at back onto the ip_enrichment rows
 * that ReportStore::touchEnrichment() seeded (source_ip + last_seen only)
 * during ingestion.
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use App\Config;
use App\Database;
use App\Enrichment\EnrichmentService;
use App\Enrichment\EspHeuristic;
use App\Enrichment\GeoLite2AsnLookup;
use App\Enrichment\IpEnrichmentRepository;
use App\Enrichment\KnownSenderMatcher;
use App\Enrichment\NullAsnLookup;
use App\Enrichment\SystemRdnsResolver;

$config = Config::load();
$pdo    = Database::connect($config);

$asnDbPath = (string) $config->get('enrichment.geolite2_asn_db', '');

// The GeoLite2 DB is a manually-provisioned, license-gated file that won't
// exist by default — degrade to no ASN data rather than fail the run.
if ($asnDbPath !== '' && is_readable($asnDbPath)) {
    $asnLookup = new GeoLite2AsnLookup($asnDbPath);
} else {
    fwrite(STDERR, "[warn] GeoLite2 ASN DB not readable at '$asnDbPath' — ASN lookups skipped\n");
    $asnLookup = new NullAsnLookup();
}

/** @var array<int, string> $knownEspAsns */
$knownEspAsns = $config->get('enrichment.known_esp_asns', []);

$service = new EnrichmentService(
    new SystemRdnsResolver(),
    $asnLookup,
    KnownSenderMatcher::fromDatabase($pdo),
    new EspHeuristic($knownEspAsns),
);

$repository = new IpEnrichmentRepository($pdo);

$limit       = (int) $config->get('enrichment.batch_limit', 500);
$refreshDays = (int) $config->get('enrichment.refresh_days', 30);

$ips = $repository->findDueForLookup($limit, $refreshDays);

$done = $failed = 0;

foreach ($ips as $ip) {
    try {
        $result = $service->enrich($ip);
        $repository->save($ip, $result);
        $done++;
    } catch (Throwable $e) {
        $failed++;
        fwrite(STDERR, "[fail] $ip: " . $e->getMessage() . "\n");
    }
}

printf("done: %d enriched, %d failed, %d due\n", $done, $failed, count($ips));
exit(0);
