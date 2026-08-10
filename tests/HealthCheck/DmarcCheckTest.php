<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck;

use App\HealthCheck\Checks\DmarcCheck;
use App\HealthCheck\HealthCheckItemResult;
use PHPUnit\Framework\TestCase;

final class DmarcCheckTest extends TestCase
{
    public function testNoRecordFails(): void
    {
        $result = (new DmarcCheck(new FakeDnsResolver()))->run('example.com');

        self::assertSame(HealthCheckItemResult::FAIL, $result[0]->status);
    }

    public function testMultipleRecordsFails(): void
    {
        $dns    = new FakeDnsResolver(['_dmarc.example.com' => ['v=DMARC1; p=reject', 'v=DMARC1; p=none']]);
        $result = (new DmarcCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::FAIL, $result[0]->status);
    }

    public function testMissingPolicyTagFails(): void
    {
        $dns    = new FakeDnsResolver(['_dmarc.example.com' => ['v=DMARC1; rua=mailto:reports@example.com']]);
        $result = (new DmarcCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::FAIL, $result[0]->status);
    }

    public function testValidReportingPolicyPasses(): void
    {
        $dns = new FakeDnsResolver([
            '_dmarc.example.com' => ['v=DMARC1; p=reject; sp=reject; rua=mailto:reports@example.com'],
        ]);
        $result = (new DmarcCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::PASS, $result[0]->status);
        self::assertSame('p=reject; sp=reject', $result[0]->detail['policy_string']);
    }

    public function testMissingRuaWarns(): void
    {
        $dns    = new FakeDnsResolver(['_dmarc.example.com' => ['v=DMARC1; p=reject']]);
        $result = (new DmarcCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::WARN, $result[0]->status);
    }

    public function testPolicyNoneWarns(): void
    {
        $dns    = new FakeDnsResolver(['_dmarc.example.com' => ['v=DMARC1; p=none; rua=mailto:reports@example.com']]);
        $result = (new DmarcCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::WARN, $result[0]->status);
    }

    /** DMARCbis (RFC 9989 §4.10) additions — docs/feature-dmarcbis.md Phase 2. */
    public function testNoOwnRecordButOrgDomainCoverageIsInfoNotFail(): void
    {
        $dns = new FakeDnsResolver(['_dmarc.example.com' => ['v=DMARC1; p=reject; sp=reject']]);

        $result = (new DmarcCheck($dns))->run('mail.example.com');

        self::assertSame(HealthCheckItemResult::INFO, $result[0]->status);
        self::assertStringContainsString('example.com', (string) $result[0]->detail['reason']);
        self::assertSame('example.com', $result[0]->detail['org_domain']);
    }

    public function testPctIsFlaggedAsRemovedButDoesNotEscalateStatus(): void
    {
        $dns    = new FakeDnsResolver(['_dmarc.example.com' => ['v=DMARC1; p=reject; sp=reject; pct=50; rua=mailto:reports@example.com']]);
        $result = (new DmarcCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::PASS, $result[0]->status);
        self::assertStringContainsString('RFC 9989', implode(' ', $result[0]->detail['issues']));
    }
}
