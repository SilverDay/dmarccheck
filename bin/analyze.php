<?php

declare(strict_types=1);

/**
 * bin/analyze.php — STUB.
 *
 * Spec §10 — the R1–R12 rule engine. Deterministic and explainable:
 * every recommendation stores the evidence that triggered it. R9 compares
 * current_published_policy against approved_baseline_policy (normalise both
 * before comparing, or cosmetic differences will cause false drift alerts).
 *
 * See the spec for full detail. Wire this up before relying on
 * it; it currently does nothing but prove the bootstrap works.
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use App\Config;
use App\Database;

$config = Config::load();
$pdo    = Database::connect($config);

fwrite(STDERR, "bin/analyze.php is a stub — not yet implemented.\n");
exit(1);
