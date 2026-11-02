<?php

declare(strict_types=1);

namespace App\Tests\Integration;

use App\HealthCheck\HealthCheckRepository;
use App\Ingest\ParsedReport;
use App\Ingest\ReportStore;
use PDO;
use PHPUnit\Framework\TestCase;

final class ReportStoreDmarcbisMigrationTest extends TestCase
{
    private PDO $pdo;

    protected function setUp(): void
    {
        $dsn = getenv('DMARC_TEST_DB_DSN');

        if ($dsn === false || $dsn === '') {
            self::markTestSkipped('Set DMARC_TEST_DB_DSN to run database integration tests.');
        }

        if (!str_starts_with($dsn, 'mysql:')) {
            self::fail('DMARC_TEST_DB_DSN must use the MySQL PDO driver.');
        }

        $user      = getenv('DMARC_TEST_DB_USER');
        $password  = getenv('DMARC_TEST_DB_PASSWORD');
        $this->pdo = new PDO(
            $dsn,
            $user     === false ? '' : $user,
            $password === false ? '' : $password,
            [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]
        );

        $this->pdo->exec(
            'CREATE TEMPORARY TABLE domains (
                id INT UNSIGNED NOT NULL PRIMARY KEY,
                active TINYINT NOT NULL DEFAULT 1,
                current_published_policy TEXT DEFAULT NULL
            ) ENGINE=InnoDB'
        );
        $this->pdo->exec(
            'CREATE TEMPORARY TABLE reports (
                id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                domain_id INT UNSIGNED NOT NULL,
                reporter_org VARCHAR(255) NOT NULL,
                report_id VARCHAR(255) NOT NULL,
                date_begin DATETIME NOT NULL,
                date_end DATETIME NOT NULL,
                raw_file_hash CHAR(64) NOT NULL,
                generator VARCHAR(255) DEFAULT NULL,
                discovery_method VARCHAR(64) DEFAULT NULL,
                UNIQUE KEY uq_report (domain_id, reporter_org, report_id),
                UNIQUE KEY uq_hash (raw_file_hash)
            ) ENGINE=InnoDB'
        );
        $this->pdo->exec(
            'CREATE TEMPORARY TABLE report_records (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                report_id INT UNSIGNED NOT NULL,
                source_ip VARBINARY(16) NOT NULL,
                `count` INT UNSIGNED NOT NULL,
                disposition VARCHAR(16) NOT NULL,
                dkim_result VARCHAR(16) NOT NULL,
                spf_result VARCHAR(16) NOT NULL,
                header_from VARCHAR(255) DEFAULT NULL,
                envelope_from VARCHAR(255) DEFAULT NULL,
                envelope_to VARCHAR(255) DEFAULT NULL
            ) ENGINE=InnoDB'
        );
        $this->pdo->exec(
            'CREATE TEMPORARY TABLE auth_results (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                record_id BIGINT UNSIGNED NOT NULL,
                type VARCHAR(16) NOT NULL,
                domain VARCHAR(255) DEFAULT NULL,
                selector VARCHAR(255) DEFAULT NULL,
                result VARCHAR(32) DEFAULT NULL
            ) ENGINE=InnoDB'
        );
        $this->pdo->exec(
            'CREATE TEMPORARY TABLE ip_enrichment (
                source_ip VARBINARY(16) NOT NULL PRIMARY KEY,
                first_seen DATETIME NOT NULL,
                last_seen DATETIME NOT NULL
            ) ENGINE=InnoDB'
        );
        $this->pdo->exec(
            'CREATE TEMPORARY TABLE health_checks (
                id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                domain_id INT UNSIGNED NOT NULL,
                run_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                trigger_ VARCHAR(32) NOT NULL DEFAULT "manual"
            ) ENGINE=InnoDB'
        );
        $this->pdo->exec(
            'CREATE TEMPORARY TABLE health_check_items (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                check_id INT UNSIGNED NOT NULL,
                category VARCHAR(32) NOT NULL,
                check_name VARCHAR(64) NOT NULL,
                status VARCHAR(16) NOT NULL,
                detail_json JSON DEFAULT NULL
            ) ENGINE=InnoDB'
        );
        $this->pdo->exec('INSERT INTO domains (id) VALUES (1)');
    }

    public function testMigrationAddsPolicyOverrideReasonsColumn(): void
    {
        $this->applyMigration();

        $columns = $this->pdo->query('SHOW COLUMNS FROM report_records LIKE "policy_override_reasons"')
            ->fetchAll();

        self::assertCount(1, $columns);
    }

    public function testReportStorePersistsAndOmitsPolicyOverrideReasons(): void
    {
        $this->applyMigration();
        $store = new ReportStore($this->pdo);

        $store->store($this->report('192.0.2.1', [
            ['type' => 'policy_test_mode', 'comment' => 'Testing policy applied'],
        ]), 1, str_repeat('a', 64));
        $store->store($this->report('192.0.2.2', []), 1, str_repeat('b', 64));

        $reasons = $this->pdo->query(
            'SELECT policy_override_reasons FROM report_records ORDER BY id'
        )->fetchAll(PDO::FETCH_COLUMN);

        self::assertSame(
            [['type' => 'policy_test_mode', 'comment' => 'Testing policy applied']],
            json_decode((string) $reasons[0], true, flags: JSON_THROW_ON_ERROR)
        );
        self::assertNull($reasons[1]);
    }

    public function testAttentionCountUsesLatestActiveDomainResultsAndIgnoresJsonNull(): void
    {
        $this->pdo->exec('INSERT INTO domains (id, active) VALUES (2, 1), (3, 1), (4, 0), (5, 1), (6, 1), (7, 1), (8, 1)');

        $this->recordDmarcItem(1, 'pass', ['pct' => null]);
        $this->recordDmarcItem(2, 'warn', ['pct' => 50]);
        $this->recordDmarcItem(3, 'fail', []);
        $this->recordDmarcItem(4, 'fail', []);
        $this->recordDmarcItem(5, 'warn', ['rf' => 'afrf']);
        $this->recordDmarcItem(5, 'pass', ['policy_string' => 'v=DMARC1; p=reject']);
        $this->recordDmarcItem(6, 'pass', ['org_domain' => 'example.com']);
        $this->recordDmarcItem(7, 'warn', ['ri' => '86400']);
        $this->recordDmarcItem(8, 'error', []);

        self::assertSame(5, (new HealthCheckRepository($this->pdo))->countDomainsNeedingDmarcbisAttention());
    }

    private function applyMigration(): void
    {
        $sql = file_get_contents(dirname(__DIR__, 2) . '/db/migrations/0007_policy_override_reasons.sql');

        self::assertNotFalse($sql);
        $this->pdo->exec($sql);
    }

    /** @param array<string, mixed> $detail */
    private function recordDmarcItem(int $domainId, string $status, array $detail): void
    {
        $stmt = $this->pdo->prepare('INSERT INTO health_checks (domain_id) VALUES (?)');
        $stmt->execute([$domainId]);
        $checkId = (int) $this->pdo->lastInsertId();

        $stmt = $this->pdo->prepare(
            'INSERT INTO health_check_items (check_id, category, check_name, status, detail_json)
             VALUES (?, ?, ?, ?, ?)'
        );
        $stmt->execute([
            $checkId,
            'dns',
            'dmarc',
            $status,
            $detail === [] ? null : json_encode($detail, JSON_THROW_ON_ERROR),
        ]);
    }

    /**
     * @param list<array{type: string, comment: ?string}> $policyOverrideReasons
     */
    private function report(string $sourceIp, array $policyOverrideReasons): ParsedReport
    {
        return new ParsedReport(
            domain: 'example.com',
            reporterOrg: 'example-reporter',
            reportId: $sourceIp,
            dateBegin: new \DateTimeImmutable('2026-01-01T00:00:00Z'),
            dateEnd: new \DateTimeImmutable('2026-01-02T00:00:00Z'),
            policyPublished: 'v=DMARC1; p=reject',
            records: [[
                'source_ip'               => $sourceIp,
                'count'                   => 1,
                'disposition'             => 'none',
                'dkim_result'             => 'pass',
                'spf_result'              => 'pass',
                'header_from'             => 'example.com',
                'envelope_from'           => null,
                'envelope_to'             => null,
                'policy_override_reasons' => $policyOverrideReasons,
                'auth_results'            => [],
            ]]
        );
    }
}
