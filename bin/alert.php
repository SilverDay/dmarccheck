<?php

declare(strict_types=1);

/**
 * bin/alert.php — STUB.
 *
 * Spec §8 — daily alerting. Includes the heartbeat/dead-man's-switch:
 * alert when NO reports have arrived for a domain in N days, which catches a
 * broken pipeline or a tampered rua record (failure modes whose symptom is
 * absence of data).
 *
 * See the spec for full detail. Wire this up before relying on
 * it; it currently does nothing but prove the bootstrap works.
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use App\Config;
use App\Database;

$config = Config::load();
$pdo    = Database::connect($config);

fwrite(STDERR, "bin/alert.php is a stub — not yet implemented.\n");
exit(1);
