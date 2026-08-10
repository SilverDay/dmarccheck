<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck\Fix;

use App\HealthCheck\Fix\DmarcFixSuggester;
use PHPUnit\Framework\TestCase;

final class DmarcFixSuggesterTest extends TestCase
{
    public function testNoRecordSuggestsAMonitorOnlyStartingPoint(): void
    {
        $fixes = DmarcFixSuggester::suggest('example.com', [
            'reason' => 'no DMARC record found at _dmarc.example.com',
        ], 'dmarc@example.com');

        self::assertCount(1, $fixes);
        self::assertSame('_dmarc.example.com', $fixes[0]->recordName);
        self::assertSame('v=DMARC1; p=none; rua=mailto:dmarc@example.com', $fixes[0]->recordValue);
    }

    public function testMultipleRecordsIsNotAutoFixable(): void
    {
        $fixes = DmarcFixSuggester::suggest('example.com', [
            'reason'  => 'multiple DMARC records published',
            'records' => ['v=DMARC1; p=none', 'v=DMARC1; p=reject'],
        ], 'dmarc@example.com');

        self::assertSame([], $fixes);
    }

    /**
     * A domain missing rua= that also still publishes the RFC 9989
     * (DMARCbis)-removed pct= tag gets BOTH fixes independently
     * (docs/feature-dmarcbis.md Phase 3) — the missing-rua fix keeps
     * pct=50 as-is (Phase 1's "don't touch existing pct on that fix"
     * decision), the drop-pct fix addresses it separately.
     */
    public function testMissingRuaReconstructsTheExistingRecordRatherThanClobberingIt(): void
    {
        $fixes = DmarcFixSuggester::suggest('example.com', [
            'policy'           => 'reject',
            'subdomain_policy' => 'quarantine',
            'pct'              => 50,
            'adkim'            => 's',
            'aspf'             => null,
            'rua'              => [],
            'issues'           => ['no rua= aggregate report destination — reports cannot reach this tool'],
        ], 'dmarc@example.com');

        self::assertCount(2, $fixes);
        self::assertSame(
            'v=DMARC1; p=reject; sp=quarantine; pct=50; adkim=s; rua=mailto:dmarc@example.com',
            $fixes[0]->recordValue,
        );
        self::assertSame(
            'v=DMARC1; p=reject; sp=quarantine; adkim=s',
            $fixes[1]->recordValue,
        );
    }

    public function testRuaAlreadySetHasNoSuggestion(): void
    {
        $fixes = DmarcFixSuggester::suggest('example.com', [
            'policy' => 'reject',
            'rua'    => ['mailto:dmarc@example.com'],
            'issues' => [],
        ], 'dmarc@example.com');

        self::assertSame([], $fixes);
    }

    /** DMARCbis (RFC 9989) additions — docs/feature-dmarcbis.md Phase 3. */
    public function testPctPresentWithRuaAlreadySetSuggestsOnlyTheDropPctFix(): void
    {
        $fixes = DmarcFixSuggester::suggest('example.com', [
            'policy' => 'reject',
            'pct'    => 75,
            'rua'    => ['dmarc-reports@example.com'],
            'issues' => [],
        ], 'dmarc@example.com');

        self::assertCount(1, $fixes);
        self::assertSame(
            'v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com',
            $fixes[0]->recordValue,
        );
    }

    public function testNoPctPublishedHasNoDropPctSuggestion(): void
    {
        $fixes = DmarcFixSuggester::suggest('example.com', [
            'policy' => 'reject',
            'rua'    => ['dmarc-reports@example.com'],
            'issues' => [],
        ], 'dmarc@example.com');

        self::assertSame([], $fixes);
    }

    public function testPolicyNoneWarningIsNeverAutoAdvanced(): void
    {
        $fixes = DmarcFixSuggester::suggest('example.com', [
            'policy' => 'none',
            'rua'    => ['mailto:dmarc@example.com'],
            'issues' => ["policy is 'none' — monitoring only, not enforcing"],
        ], 'dmarc@example.com');

        self::assertSame([], $fixes);
    }
}
