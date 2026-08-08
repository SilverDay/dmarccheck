<?php

declare(strict_types=1);

/**
 * bin/migrate.php — applies pending SQL migrations from db/migrations/,
 * tracked in the schema_migrations table. Run manually after pulling
 * changes that touch the schema, or as part of a deploy step:
 *
 *   php bin/migrate.php            # apply everything pending
 *   php bin/migrate.php --status   # list applied/pending without running anything
 *
 * Each file in db/migrations/ is a plain .sql file, named `NNNN_description.sql`
 * (zero-padded, sorts correctly), applied in order and never edited once
 * committed — a schema change after the fact is a new numbered file.
 *
 * MySQL/MariaDB DDL causes an implicit commit per statement, so a
 * migration is NOT atomic across multiple statements — wrapping this in a
 * transaction would only be misleading. Keep each migration file to one
 * focused change. If a file fails partway through, it is NOT marked
 * applied; inspect the database by hand, fix forward (a new migration
 * file), and re-run — never re-edit a file that may have partially applied.
 *
 * Existing installations: on the very first run against a database that
 * predates this system (tables already exist, schema_migrations is empty),
 * the baseline migration is recorded as already applied rather than
 * re-executed — see the adoption step below.
 */

require dirname(__DIR__) . '/vendor/autoload.php';

use App\Config;
use App\Database;

$config = Config::load();
$pdo    = Database::connect($config);

$pdo->exec(
    'CREATE TABLE IF NOT EXISTS schema_migrations (
        migration  VARCHAR(255) NOT NULL,
        applied_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (migration)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4'
);

$migrationsDir = dirname(__DIR__) . '/db/migrations';
$files         = glob($migrationsDir . '/*.sql') ?: [];
sort($files, SORT_STRING);

/** @var list<string> $appliedList */
$appliedList = array_map('strval', $pdo->query('SELECT migration FROM schema_migrations')->fetchAll(PDO::FETCH_COLUMN));
$applied     = array_flip($appliedList);

$statusOnly = \in_array('--status', $argv, true);

// Adopt an existing, pre-migrations database: if nothing has been recorded
// yet but the baseline's tables are already present, mark the baseline
// applied without re-running its CREATE TABLE statements. --status must
// stay read-only, so it reports what adoption *would* do without writing.
if ($applied === [] && $files !== []) {
    $baseline = basename($files[0]);
    $exists   = (int) $pdo->query(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'domains'"
    )->fetchColumn();

    if ($exists > 0 && $statusOnly) {
        printf("[adopt-pending] %s — tables already exist; will be recorded as applied (not re-run) on next non-status run\n", $baseline);
        $applied[$baseline] = true;
    } elseif ($exists > 0) {
        $pdo->prepare('INSERT INTO schema_migrations (migration) VALUES (?)')->execute([$baseline]);
        $applied[$baseline] = true;
        printf("[adopt] %s already applied on this database — recording without re-running\n", $baseline);
    }
}

$ranAny = false;

foreach ($files as $file) {
    $name = basename($file);

    if ($statusOnly) {
        printf("%s  %s\n", isset($applied[$name]) ? '[applied]' : '[pending]', $name);

        continue;
    }

    if (isset($applied[$name])) {
        continue;
    }

    printf("[migrate] applying %s\n", $name);
    $sql = file_get_contents($file);

    if ($sql === false) {
        fwrite(STDERR, "FATAL: could not read $file\n");
        exit(1);
    }

    try {
        $pdo->exec($sql);
    } catch (PDOException $e) {
        fwrite(STDERR, "FATAL: $name failed: " . $e->getMessage() . "\n");
        fwrite(STDERR, "Not marked as applied. Inspect the database, fix forward with a new migration, and re-run.\n");
        exit(1);
    }

    $pdo->prepare('INSERT INTO schema_migrations (migration) VALUES (?)')->execute([$name]);
    $ranAny = true;
}

if ($statusOnly) {
    exit(0);
}

echo $ranAny ? "done: migrations applied\n" : "done: nothing to apply\n";
exit(0);
