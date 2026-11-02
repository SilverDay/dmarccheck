<?php

declare(strict_types=1);

/**
 * bin/alert.php — spec §8. Daily alerting: heartbeat/dead-man's-switch (no
 * reports in N days), unknown-sender volume spikes, DMARC pass-rate
 * regression vs. trailing average, and DNS policy drift from the approved
 * baseline. Findings across all domains are combined into one digest email
 * (via App\Auth\Mailer, the existing local-MTA sender) rather than one per
 * domain/condition. A condition that's still true on the next run re-alerts
 * — no suppression/dedup state — matching the heartbeat's own purpose of
 * surfacing a persisting problem rather than a one-off blip.
 *
 *   php bin/alert.php                # every active domain
 *   php bin/alert.php example.com     # one domain
 *
 * 0   5 * * *  php /srv/dmarc/bin/alert.php >> /var/log/dmarc-alert.log 2>&1
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use App\Alerting\AlertContextBuilder;
use App\Alerting\Checks\AlertCheck;
use App\Alerting\Checks\HeartbeatCheck;
use App\Alerting\Checks\PassRateRegressionCheck;
use App\Alerting\Checks\PolicyDriftCheck;
use App\Alerting\Checks\UnknownVolumeCheck;
use App\Alerting\Webhook\StreamWebhookHttpClient;
use App\Alerting\Webhook\WebhookDestination;
use App\Alerting\Webhook\WebhookSender;
use App\Auth\AuditLog;
use App\Auth\Mailer;
use App\Config;
use App\Database;
use InvalidArgumentException;
use Throwable;

$config = Config::load();
$pdo    = Database::connect($config);

$heartbeatDays        = (int) $config->get('alerting.heartbeat_days', 3);
$volumeThreshold      = (int) $config->get('alerting.unknown_ip_volume', 50);
$dropPctThreshold     = (float) $config->get('alerting.pass_rate_drop_pct', 10);
$windowDays           = (int) $config->get('alerting.window_days', 1);
$passRateBaselineDays = (int) $config->get('alerting.pass_rate_baseline_days', 30);
$passRateMinCount     = (int) $config->get('alerting.pass_rate_min_count', 50);
$mailTo               = (string) $config->require('alerting.to');
$mailFrom             = (string) $config->require('alerting.from');

$contextBuilder = new AlertContextBuilder($pdo, $windowDays, $passRateBaselineDays);

/** @var list<AlertCheck> $checks */
$checks = [
    new HeartbeatCheck($heartbeatDays),
    new PolicyDriftCheck(),
    new UnknownVolumeCheck($volumeThreshold),
    new PassRateRegressionCheck($dropPctThreshold, $passRateMinCount),
];

$domainArg = $argv[1] ?? null;

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

/** @var list<\App\Alerting\AlertFinding> $allFindings */
$allFindings = [];

foreach ($domains as $row) {
    $domainId = (int) $row['id'];
    $domain   = (string) $row['domain'];

    try {
        $context = $contextBuilder->build($domainId, $domain);

        $findings = [];
        foreach ($checks as $check) {
            $findings = [...$findings, ...$check->evaluate($context)];
        }

        $allFindings = [...$allFindings, ...$findings];

        printf("[ok] %s — %d finding(s)\n", $domain, \count($findings));
    } catch (Throwable $e) {
        fwrite(STDERR, "[fail] $domain: " . $e->getMessage() . "\n");
    }
}

if ($allFindings === []) {
    printf("[ok] no alerts across %d domain(s)\n", \count($domains));
    exit(0);
}

/** @var array<string, list<\App\Alerting\AlertFinding>> $byDomain */
$byDomain = [];

foreach ($allFindings as $finding) {
    $byDomain[$finding->domain][] = $finding;
}

$body = '';

foreach ($byDomain as $domain => $findings) {
    $body .= "$domain:\n";

    foreach ($findings as $finding) {
        $body .= "  - {$finding->message}\n";
    }

    $body .= "\n";
}

$subject = sprintf(
    'DMARC Analyzer alert: %d finding(s) across %d domain(s)',
    \count($allFindings),
    \count($byDomain)
);

$sent = (new Mailer($mailFrom))->send($mailTo, $subject, $body);

if (!$sent) {
    fwrite(STDERR, "FATAL: failed to send alert digest email to $mailTo\n");
} else {
    printf("[sent] %d finding(s) across %d domain(s) to %s\n", \count($allFindings), \count($byDomain), $mailTo);
}

$configuredWebhooks = $config->get('alerting.webhooks', []);

if (!\is_array($configuredWebhooks) || !array_is_list($configuredWebhooks)) {
    fwrite(STDERR, "[webhook-config-failed] alerting.webhooks must be a list.\n");
    exit($sent ? 0 : 1);
}

$destinations = [];

try {
    $destinationNames = [];

    foreach ($configuredWebhooks as $webhookConfig) {
        if (!\is_array($webhookConfig)) {
            throw new InvalidArgumentException('Each webhook destination must be a configuration object.');
        }

        $destination = WebhookDestination::fromEnvironment($webhookConfig);

        if (isset($destinationNames[$destination->name])) {
            throw new InvalidArgumentException('Webhook destination names must be unique.');
        }

        $destinationNames[$destination->name] = true;
        $destinations[]                       = $destination;
    }
} catch (InvalidArgumentException $e) {
    fwrite(STDERR, "[webhook-config-failed] " . $e->getMessage() . "\n");
    exit($sent ? 0 : 1);
}

$audit = new AuditLog($pdo);

foreach ((new WebhookSender(new StreamWebhookHttpClient(), $destinations))->send($allFindings) as $delivery) {
    try {
        $audit->record(null, 'alert.webhook_delivery', $delivery->destination, [
            'event_type'    => $delivery->eventType,
            'domain'        => $delivery->domain,
            'event_id'      => $delivery->eventId,
            'success'       => $delivery->success,
            'attempts'      => $delivery->attempts,
            'http_statuses' => $delivery->httpStatuses,
        ]);
    } catch (Throwable) {
        fwrite(STDERR, "[webhook-audit-failed] Could not record delivery outcome for {$delivery->destination}.\n");
    }

    if (!$delivery->success) {
        fwrite(
            STDERR,
            "[webhook-failed] {$delivery->destination} {$delivery->eventType} for {$delivery->domain}; "
                . "{$delivery->attempts} attempt(s), HTTP statuses: "
                . implode(',', array_map(static fn (?int $status): string => $status === null ? 'transport-error' : (string) $status, $delivery->httpStatuses))
                . "\n"
        );
    } else {
        printf("[webhook-sent] %s %s for %s\n", $delivery->destination, $delivery->eventType, $delivery->domain);
    }
}

exit($sent ? 0 : 1);
