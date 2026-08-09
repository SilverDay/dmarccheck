<?php

declare(strict_types=1);

/**
 * bin/retention.php — spec §13/§14. Off by default — spec §14 frames the
 * retention window as a DPO/operator policy decision, not something this
 * tool assumes; set retention.reports_years/retention.ip_enrichment_years
 * in config.php to enable pruning (see config.sample.php). Run from cron:
 *
 *   0 3 1 * *  php /srv/dmarc/bin/retention.php >> /var/log/dmarc-retention.log 2>&1
 *
 *   php bin/retention.php             # prune per the configured windows
 *   php bin/retention.php --dry-run   # report what would be deleted, change nothing
 *
 * report_records/auth_results have no date of their own — dates live on
 * the parent `reports` row, so pruning deletes old `reports` rows and lets
 * ON DELETE CASCADE take the rest. ip_enrichment is pruned independently
 * on its own last_seen cutoff. Raw archived XML/JSON under archive/ is
 * never touched here — spec §13 is explicit that it's retained
 * indefinitely regardless (cheap, and needed to allow re-parsing after
 * parser bug fixes).
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use App\Auth\AuditLog;
use App\Config;
use App\Database;

$config = Config::load();
$pdo    = Database::connect($config);
$audit  = new AuditLog($pdo);

$dryRun = \in_array('--dry-run', $argv, true);

$reportYears = (int) $config->get('retention.reports_years', 0);
$ipYears     = (int) $config->get('retention.ip_enrichment_years', 0);

$reportsDeleted = 0;
$ipDeleted      = 0;

if ($reportYears > 0) {
    if ($dryRun) {
        $reportsDeleted = (int) $pdo->query(
            "SELECT COUNT(*) FROM reports WHERE date_begin < NOW() - INTERVAL $reportYears YEAR"
        )->fetchColumn();
    } else {
        $stmt = $pdo->prepare("DELETE FROM reports WHERE date_begin < NOW() - INTERVAL $reportYears YEAR");
        $stmt->execute();
        $reportsDeleted = $stmt->rowCount();
    }
} else {
    fwrite(STDERR, "[skip] retention.reports_years not set — reports/report_records/auth_results retained indefinitely\n");
}

if ($ipYears > 0) {
    if ($dryRun) {
        $ipDeleted = (int) $pdo->query(
            "SELECT COUNT(*) FROM ip_enrichment WHERE last_seen < NOW() - INTERVAL $ipYears YEAR"
        )->fetchColumn();
    } else {
        $stmt = $pdo->prepare("DELETE FROM ip_enrichment WHERE last_seen < NOW() - INTERVAL $ipYears YEAR");
        $stmt->execute();
        $ipDeleted = $stmt->rowCount();
    }
} else {
    fwrite(STDERR, "[skip] retention.ip_enrichment_years not set — ip_enrichment retained indefinitely\n");
}

printf(
    "%s: %d report(s), %d ip_enrichment row(s)%s\n",
    $dryRun ? 'would delete' : 'deleted',
    $reportsDeleted,
    $ipDeleted,
    $dryRun ? ' (--dry-run, nothing changed)' : ''
);

if (!$dryRun && ($reportsDeleted > 0 || $ipDeleted > 0)) {
    $audit->record(null, 'retention.pruned', null, [
        'reports_deleted'       => $reportsDeleted,
        'ip_enrichment_deleted' => $ipDeleted,
        'reports_years'         => $reportYears,
        'ip_enrichment_years'   => $ipYears,
    ], null);
}
