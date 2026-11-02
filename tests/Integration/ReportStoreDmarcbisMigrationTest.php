<?php

declare(strict_types=1);

namespace App\Tests\Integration;

use App\HealthCheck\HealthCheckRepository;
use App\Ingest\ParsedReport;
use App\Ingest\ReportStore;
use App\Recommendation\RecommendationRow;
use App\Recommendation\ReportAuthEvidenceRepository;
use App\Reports\ReportSearchCriteria;
use App\Reports\ReportSearchRepository;
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
                domain VARCHAR(255) NOT NULL,
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
                rdns VARCHAR(255) DEFAULT NULL,
                asn INT UNSIGNED DEFAULT NULL,
                asn_org VARCHAR(255) DEFAULT NULL,
                label VARCHAR(64) NOT NULL DEFAULT "unknown",
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
        $this->pdo->exec("INSERT INTO domains (id, domain) VALUES (1, 'example.com')");
    }

    public function testMigrationAddsPolicyOverrideReasonsColumn(): void
    {
        $this->applyMigration();

        $columns = $this->pdo->query('SHOW COLUMNS FROM report_records LIKE "policy_override_reasons"')
            ->fetchAll();

        self::assertCount(1, $columns);
    }

    public function testReportSearchMigrationAddsDateRangeIndex(): void
    {
        $sql = file_get_contents(dirname(__DIR__, 2) . '/db/migrations/0008_report_search_date_index.sql');

        self::assertNotFalse($sql);
        $this->pdo->exec($sql);

        $indexes = $this->pdo->query('SHOW INDEX FROM reports WHERE Key_name = "idx_report_date_begin"')->fetchAll();

        self::assertCount(1, $indexes);
        self::assertSame('date_begin', $indexes[0]['Column_name']);
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
        $this->pdo->exec("INSERT INTO domains (id, domain, active) VALUES
            (2, 'two.example', 1), (3, 'three.example', 1), (4, 'four.example', 0),
            (5, 'five.example', 1), (6, 'six.example', 1), (7, 'seven.example', 1), (8, 'eight.example', 1)");

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

    public function testReportSearchAppliesCombinedDomainAndRecordFilters(): void
    {
        $this->applyMigration();
        $this->applySearchIndexMigration();
        $this->pdo->exec("INSERT INTO domains (id, domain) VALUES (2, 'other.example')");
        $store = new ReportStore($this->pdo);
        $store->store($this->report('192.0.2.1', [], 'fail', 'pass', 'reject', 9), 1, str_repeat('c', 64));
        $store->store($this->report('192.0.2.2', [], 'pass', 'pass', 'none', 3), 1, str_repeat('d', 64));
        $store->store($this->report('198.51.100.1', [], 'fail', 'pass', 'reject', 5), 2, str_repeat('e', 64));

        $this->pdo->exec("UPDATE ip_enrichment SET label = 'unknown', asn_org = 'Example Mail Network', rdns = 'mx.example.test'");
        $this->pdo->prepare("UPDATE ip_enrichment SET label = 'trusted', asn_org = 'Example Mail Network' WHERE source_ip = INET6_ATON(?)")
            ->execute(['198.51.100.1']);

        $criteria = ReportSearchCriteria::fromQuery([
            'domain'      => '1',
            'range'       => 'custom',
            'from'        => '2026-01-01',
            'to'          => '2026-01-01',
            'label'       => 'unknown',
            'dkim'        => 'fail',
            'spf'         => 'pass',
            'disposition' => 'reject',
            'asn_org'     => 'Mail Network',
        ]);
        $rows = (new ReportSearchRepository($this->pdo))->search($criteria, 20);

        self::assertCount(1, $rows);
        self::assertSame('example.com', $rows[0]['domain']);
        self::assertSame('192.0.2.1', $rows[0]['source_ip']);
        self::assertSame(9, $rows[0]['volume']);
        self::assertSame('192.0.2.1', $rows[0]['report_id']);
    }

    public function testReportSearchTreatsLikeWildcardsAsLiteralText(): void
    {
        $this->applyMigration();
        $this->applySearchIndexMigration();
        $store = new ReportStore($this->pdo);
        $store->store($this->report('192.0.2.1', []), 1, str_repeat('f', 64));
        $this->pdo->exec("UPDATE ip_enrichment SET asn_org = 'Example Mail Network'");

        $criteria = ReportSearchCriteria::fromQuery([
            'domain'  => '1',
            'range'   => 'custom',
            'from'    => '2026-01-01',
            'to'      => '2026-01-01',
            'asn_org' => 'Mail%',
        ]);

        self::assertSame([], (new ReportSearchRepository($this->pdo))->search($criteria, 20));
    }

    public function testReportSearchCanFindRecordsWithoutEnrichment(): void
    {
        $this->applyMigration();
        $store = new ReportStore($this->pdo);
        $store->store($this->report('192.0.2.1', []), 1, str_repeat('g', 64));
        $this->pdo->exec('DELETE FROM ip_enrichment');

        $criteria = ReportSearchCriteria::fromQuery([
            'domain' => '1',
            'range'  => 'custom',
            'from'   => '2026-01-01',
            'to'     => '2026-01-01',
            'label'  => 'pending',
        ]);
        $rows = (new ReportSearchRepository($this->pdo))->search($criteria, 20);

        self::assertCount(1, $rows);
        self::assertSame('pending', $rows[0]['label']);
    }

    public function testReportAuthEvidenceMapsR1SpfAndR2DkimIdentitiesToFindings(): void
    {
        $this->applyMigration();
        $store = new ReportStore($this->pdo);
        $date  = new \DateTimeImmutable('-1 day');
        $store->store($this->report('192.0.2.1', [], 'pass', 'fail', 'none', 4, [
            ['type' => 'spf', 'domain' => 'mail.example.com', 'selector' => null, 'result' => 'fail'],
        ], $date), 1, str_repeat('h', 64));
        $store->store($this->report('192.0.2.2', [], 'fail', 'pass', 'none', 3, [
            ['type' => 'dkim', 'domain' => 'example.com', 'selector' => 's1', 'result' => 'fail'],
        ], $date), 1, str_repeat('i', 64));

        $recommendations = [
            new RecommendationRow(11, 'R1', 'low', '192.0.2.1', ['window_days' => 7], 'now', 'now', 'open'),
            new RecommendationRow(12, 'R2', 'low', '192.0.2.2', ['window_days' => 7], 'now', 'now', 'open'),
        ];
        $result = (new ReportAuthEvidenceRepository($this->pdo))->forRecommendations(1, $recommendations);

        self::assertSame(['mail.example.com'], $result['findings'][11]['spf_domains']);
        self::assertSame([['domain' => 'example.com', 'selector' => 's1']], $result['findings'][12]['dkim_signatures']);
        self::assertFalse($result['truncated']);
    }

    private function applyMigration(): void
    {
        $sql = file_get_contents(dirname(__DIR__, 2) . '/db/migrations/0007_policy_override_reasons.sql');

        self::assertNotFalse($sql);
        $this->pdo->exec($sql);
    }

    private function applySearchIndexMigration(): void
    {
        $sql = file_get_contents(dirname(__DIR__, 2) . '/db/migrations/0008_report_search_date_index.sql');

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
    /**
     * @param list<array{type: string, domain: ?string, selector: ?string, result: ?string}> $authResults
     */
    private function report(
        string $sourceIp,
        array $policyOverrideReasons,
        string $dkimResult = 'pass',
        string $spfResult = 'pass',
        string $disposition = 'none',
        int $count = 1,
        array $authResults = [],
        ?\DateTimeImmutable $dateBegin = null,
    ): ParsedReport {
        $dateBegin ??= new \DateTimeImmutable('2026-01-01T00:00:00Z');

        return new ParsedReport(
            domain: 'example.com',
            reporterOrg: 'example-reporter',
            reportId: $sourceIp,
            dateBegin: $dateBegin,
            dateEnd: $dateBegin->modify('+1 day'),
            policyPublished: 'v=DMARC1; p=reject',
            records: [[
                'source_ip'               => $sourceIp,
                'count'                   => $count,
                'disposition'             => $disposition,
                'dkim_result'             => $dkimResult,
                'spf_result'              => $spfResult,
                'header_from'             => 'example.com',
                'envelope_from'           => null,
                'envelope_to'             => null,
                'policy_override_reasons' => $policyOverrideReasons,
                'auth_results'            => $authResults,
            ]]
        );
    }
}
