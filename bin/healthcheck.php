<?php

declare(strict_types=1);

/**
 * bin/healthcheck.php — STUB.
 *
 * Spec §11 — per-domain DNS/transport/reputation posture check.
 * Remember: an un-run check is NOT a passing check. A DNSBL timeout or the
 * Spamhaus 127.255.255.254 sentinel must record status=error, never pass.
 *
 * See the spec for full detail. Wire this up before relying on
 * it; it currently does nothing but prove the bootstrap works.
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use App\Config;
use App\Database;

$config = Config::load();
$pdo    = Database::connect($config);

fwrite(STDERR, "bin/healthcheck.php is a stub — not yet implemented.\n");
exit(1);
