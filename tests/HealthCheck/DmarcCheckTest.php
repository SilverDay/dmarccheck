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

    public function testInheritedPolicyIncludesReadinessTags(): void
    {
        $dns = new FakeDnsResolver([
            '_dmarc.example.com' => ['v=DMARC1; p=reject; pct=100; rf=afrf; ri=86400; np=quarantine; psd=n; t=n'],
        ]);

        $result = (new DmarcCheck($dns))->run('mail.example.com');

        self::assertSame(HealthCheckItemResult::INFO, $result[0]->status);
        self::assertSame(100, $result[0]->detail['pct']);
        self::assertSame('afrf', $result[0]->detail['rf']);
        self::assertSame('86400', $result[0]->detail['ri']);
        self::assertSame('quarantine', $result[0]->detail['non_existent_subdomain_policy']);
        self::assertSame('n', $result[0]->detail['psd']);
        self::assertSame('n', $result[0]->detail['testing']);
        self::assertSame([], $result[0]->detail['invalid_dmarcbis_tags']);
    }

    public function testInvalidDmarcbisTagValuesWarnWithoutBreakingTheDmarcPolicy(): void
    {
        $dns = new FakeDnsResolver([
            '_dmarc.example.com' => ['v=DMARC1; p=reject; np=full; psd=u; t=maybe; rua=mailto:reports@example.com'],
        ]);
        $result = (new DmarcCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::WARN, $result[0]->status);
        self::assertSame(['np' => 'full', 'psd' => 'u', 't' => 'maybe'], $result[0]->detail['invalid_dmarcbis_tags']);
        self::assertSame('p=reject; np=full; psd=u; t=maybe', $result[0]->detail['policy_string']);
        self::assertStringContainsString('np=full, psd=u, t=maybe', implode(' ', $result[0]->detail['issues']));
    }

    public function testInheritedPolicyAlsoSurfacesInvalidDmarcbisTags(): void
    {
        $dns = new FakeDnsResolver([
            '_dmarc.example.com' => ['v=DMARC1; p=reject; np=full; psd=u; t=maybe'],
        ]);
        $result = (new DmarcCheck($dns))->run('mail.example.com');

        self::assertSame(HealthCheckItemResult::WARN, $result[0]->status);
        self::assertSame('example.com', $result[0]->detail['org_domain']);
        self::assertSame(['np' => 'full', 'psd' => 'u', 't' => 'maybe'], $result[0]->detail['invalid_dmarcbis_tags']);
    }

    public function testPctIsFlaggedAsRemovedButDoesNotEscalateStatus(): void
    {
        $dns    = new FakeDnsResolver(['_dmarc.example.com' => ['v=DMARC1; p=reject; sp=reject; pct=50; rua=mailto:reports@example.com']]);
        $result = (new DmarcCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::PASS, $result[0]->status);
        self::assertStringContainsString('RFC 9989', implode(' ', $result[0]->detail['issues']));
    }

    public function testDeprecatedReportTagsAreInformationalAndPsDIsInPolicyString(): void
    {
        $dns = new FakeDnsResolver([
            '_dmarc.example.com' => ['v=DMARC1; p=reject; psd=n; rf=afrf; ri=86400; fo=1:d; rua=mailto:reports@example.com'],
        ]);
        $result = (new DmarcCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::PASS, $result[0]->status);
        self::assertSame('afrf', $result[0]->detail['rf']);
        self::assertSame('86400', $result[0]->detail['ri']);
        self::assertSame('1:d', $result[0]->detail['fo']);
        self::assertStringContainsString('psd=n', $result[0]->detail['policy_string']);
        self::assertCount(2, $result[0]->detail['issues']);
    }

    public function testRemovingPartialPctIsNotDescribedAsBehaviorNeutral(): void
    {
        $dns = new FakeDnsResolver([
            '_dmarc.example.com' => ['v=DMARC1; p=reject; pct=25; rua=mailto:reports@example.com'],
        ]);
        $result = (new DmarcCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::PASS, $result[0]->status);
        self::assertStringContainsString('increase enforcement', implode(' ', $result[0]->detail['issues']));
    }
}
