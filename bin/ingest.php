<?php

declare(strict_types=1);

/**
 * bin/ingest.php — spec §4. Run from cron every 15–30 min:
 *
 *   * /20 * * * *  php /srv/dmarc/bin/ingest.php >> /var/log/dmarc-ingest.log 2>&1
 *
 * Pull model (IMAP poll) is deliberate: the mailbox acts as a buffer and
 * retry queue, and parsing never runs inside the mail delivery path.
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use App\Config;
use App\Database;
use App\Ingest\Decompressor;
use App\Ingest\ReportParser;
use App\Ingest\ReportStore;
use App\Ingest\SenderRateLimiter;
use Webklex\PHPIMAP\Address;
use Webklex\PHPIMAP\ClientManager;
use Webklex\PHPIMAP\Message;

$config = Config::load();
$pdo    = Database::connect($config);
$store  = new ReportStore($pdo);
$parser = new ReportParser();

$decompressor = new Decompressor(
    (int) $config->get('ingest.max_decompressed_bytes', 50 * 1024 * 1024),
    (int) $config->get('ingest.max_zip_entries', 16),
);

// §4.1 — per-sender rate/volume caps, so one hostile/misbehaving sender
// can't flood a run's processing budget or the mailbox itself.
$rateLimiter = new SenderRateLimiter(
    $pdo,
    (int) $config->get('ingest.rate_limit.window_minutes', 60),
    (int) $config->get('ingest.rate_limit.max_messages', 50),
);

$archivePath = (string) $config->get('ingest.archive_path', dirname(__DIR__) . '/archive');
@mkdir($archivePath, 0750, true);

/** Best-effort sender extraction; a missing/unparsable From header must never abort the run. */
function ingest_sender(Message $message): string
{
    try {
        $from = $message->from->first();
    } catch (Throwable) {
        return 'unknown';
    }

    return $from instanceof Address && $from->mail !== ''
        ? strtolower(trim($from->mail))
        : 'unknown';
}

$runStmt = $pdo->prepare('INSERT INTO ingest_runs (status) VALUES (?)');
$runStmt->execute(['running']);
$runId = (int) $pdo->lastInsertId();

$seen = $stored = $failed = 0;

try {
    $client = (new ClientManager())->make([
        'host'          => $config->require('imap.host'),
        'port'          => (int) $config->get('imap.port', 993),
        'protocol'      => (string) $config->get('imap.protocol', 'imap'),
        'encryption'    => (string) $config->get('imap.encryption', 'ssl'),
        'validate_cert' => (bool) $config->get('imap.validate_cert', true),
        'username'      => $config->require('imap.username'),
        'password'      => $config->require('imap.password'),
    ]);

    $client->connect();

    $inbox           = $client->getFolderByPath((string) $config->get('imap.folder_inbox', 'INBOX'));
    $done            = (string) $config->get('imap.folder_done', 'INBOX.Processed');
    $failedFolder    = (string) $config->get('imap.folder_failed', 'INBOX.Failed');
    $limit           = (int) $config->get('ingest.batch_limit', 200);
    $maxAttachment   = (int) $config->get('ingest.max_attachment_bytes', 10 * 1024 * 1024);
    $maxMessageBytes = (int) $config->get('ingest.max_message_bytes', 20 * 1024 * 1024);

    $messages = $inbox->query()->unseen()->limit($limit)->get();

    foreach ($messages as $message) {
        $seen++;
        $handled  = false;
        $hadError = false;

        $sender = ingest_sender($message);
        if (!$rateLimiter->allow($sender)) {
            fwrite(STDERR, "[skip] sender rate limit exceeded: $sender\n");
            $failed++;
            try {
                $message->move($failedFolder);
            } catch (Throwable $e) {
                fwrite(STDERR, '[fail] could not move message: ' . $e->getMessage() . "\n");
            }
            continue;
        }

        $messageBytes = 0;

        foreach ($message->getAttachments() as $attachment) {
            $payload = (string) $attachment->getContent();
            $messageBytes += strlen($payload);

            // §4.1 — reject oversized input before doing any work on it.
            if ($messageBytes > $maxMessageBytes) {
                fwrite(STDERR, "[skip] message exceeds total size cap\n");
                $hadError = true;
                break;
            }

            if (strlen($payload) > $maxAttachment) {
                fwrite(STDERR, "[skip] attachment exceeds size cap\n");
                $hadError = true;
                continue;
            }

            try {
                $xml  = $decompressor->decompress($payload);
                $hash = hash('sha256', $xml);

                if ($store->alreadyIngested($hash)) {
                    $handled = true;
                    continue;
                }

                $report   = $parser->parse($xml);
                $domainId = $store->findDomainId($report->domain);

                if ($domainId === null) {
                    fwrite(STDERR, "[skip] report for unmanaged domain: {$report->domain}\n");
                    $hadError = true;
                    continue;
                }

                // Archive raw XML first — internal filename from the content
                // hash, never from the attacker-supplied attachment name.
                file_put_contents(
                    $archivePath . '/' . $hash . '.xml.gz',
                    gzencode($xml, 6)
                );

                $reportRowId = $store->store($report, $domainId, $hash);

                if ($reportRowId !== null) {
                    $stored++;
                    printf(
                        "[ok] %s from %s — %d records, %d messages%s\n",
                        $report->domain,
                        $report->reporterOrg,
                        $report->recordCount(),
                        $report->messageCount(),
                        $report->warnings === [] ? '' : ' (' . count($report->warnings) . ' skipped)'
                    );
                }

                foreach ($report->warnings as $warning) {
                    fwrite(STDERR, "[warn] $warning\n");
                }

                $handled = true;
            } catch (Throwable $e) {
                $hadError = true;
                fwrite(STDERR, '[fail] ' . $e->getMessage() . "\n");
            }
        }

        // Quarantine anything that failed so it can be inspected — never
        // silently dropped (§4 step 3g). A message with a mix of successful
        // and failed attachments still goes to quarantine rather than done:
        // store()/archive are idempotent on content hash, so re-inspecting
        // or re-running ingestion against it cannot double-store the parts
        // that already succeeded.
        if ($hadError) {
            $failed++;
            try {
                $message->move($failedFolder);
            } catch (Throwable $e) {
                fwrite(STDERR, '[fail] could not move message: ' . $e->getMessage() . "\n");
            }
        } elseif ($handled) {
            try {
                $message->move($done);
            } catch (Throwable $e) {
                fwrite(STDERR, '[warn] could not move message: ' . $e->getMessage() . "\n");
            }
        }
    }

    $client->disconnect();

    $pdo->prepare(
        'UPDATE ingest_runs
            SET finished_at = NOW(), messages_seen = ?, reports_stored = ?, failures = ?, status = ?
          WHERE id = ?'
    )->execute([$seen, $stored, $failed, 'ok', $runId]);

    printf("done: %d seen, %d stored, %d failed\n", $seen, $stored, $failed);
    exit(0);
} catch (Throwable $e) {
    $pdo->prepare(
        'UPDATE ingest_runs
            SET finished_at = NOW(), messages_seen = ?, reports_stored = ?, failures = ?, status = ?, detail = ?
          WHERE id = ?'
    )->execute([$seen, $stored, $failed, 'error', $e->getMessage(), $runId]);

    fwrite(STDERR, 'FATAL: ' . $e->getMessage() . "\n");
    exit(1);
}
