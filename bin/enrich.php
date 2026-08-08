<?php

declare(strict_types=1);

/**
 * bin/enrich.php — STUB.
 *
 * Spec §6 — rDNS + ASN lookup (local GeoLite2 DB), known_senders CIDR
 * matching, and known/unknown labelling. Runs decoupled from ingestion so a
 * slow DNS lookup never blocks report parsing.
 *
 * See the spec for full detail. Wire this up before relying on
 * it; it currently does nothing but prove the bootstrap works.
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use App\Config;
use App\Database;

$config = Config::load();
$pdo    = Database::connect($config);

fwrite(STDERR, "bin/enrich.php is a stub — not yet implemented.\n");
exit(1);
