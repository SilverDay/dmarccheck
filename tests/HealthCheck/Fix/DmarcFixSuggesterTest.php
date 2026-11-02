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

    public function testMissingRuaReconstructsTheExistingRecordRatherThanClobberingIt(): void
    {
        $fixes = DmarcFixSuggester::suggest('example.com', [
            'policy'                        => 'reject',
            'subdomain_policy'              => 'quarantine',
            'non_existent_subdomain_policy' => 'reject',
            'psd'                           => 'n',
            'pct'                           => 50,
            'adkim'                         => 's',
            'testing'                       => 'y',
            'rf'                            => 'afrf',
            'ri'                            => '86400',
            'fo'                            => '1:d',
            'rua'                           => [],
            'ruf'                           => ['failures@example.com'],
            'issues'                        => ['no rua= aggregate report destination — reports cannot reach this tool'],
        ], 'dmarc@example.com');

        self::assertCount(1, $fixes);
        self::assertSame(
            'v=DMARC1; p=reject; sp=quarantine; np=reject; psd=n; pct=50; adkim=s; t=y; rf=afrf; ri=86400; fo=1:d; rua=mailto:dmarc@example.com; ruf=mailto:failures@example.com',
            $fixes[0]->recordValue,
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
            'pct'    => 100,
            'rua'    => ['dmarc-reports@example.com'],
            'issues' => [],
        ], 'dmarc@example.com');

        self::assertCount(1, $fixes);
        self::assertSame(
            'v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com',
            $fixes[0]->recordValue,
        );
    }

    public function testDropPctFixPreservesOtherRecognizedPolicyAndReportTags(): void
    {
        $fixes = DmarcFixSuggester::suggest('example.com', [
            'policy'                        => 'reject',
            'subdomain_policy'              => 'quarantine',
            'non_existent_subdomain_policy' => 'reject',
            'psd'                           => 'n',
            'pct'                           => 100,
            'testing'                       => 'y',
            'rf'                            => 'afrf',
            'ri'                            => '86400',
            'fo'                            => '1:d',
            'rua'                           => ['reports@example.com'],
            'ruf'                           => ['failures@example.com'],
        ], 'dmarc@example.com');

        self::assertCount(1, $fixes);
        self::assertSame(
            'v=DMARC1; p=reject; sp=quarantine; np=reject; psd=n; t=y; rf=afrf; ri=86400; fo=1:d; rua=mailto:reports@example.com; ruf=mailto:failures@example.com',
            $fixes[0]->recordValue,
        );
    }

    public function testDoesNotOfferDropPctFixWhenItWouldIncreaseEnforcement(): void
    {
        $fixes = DmarcFixSuggester::suggest('example.com', [
            'policy' => 'reject',
            'pct'    => 25,
            'rua'    => ['reports@example.com'],
        ], 'dmarc@example.com');

        self::assertSame([], $fixes);
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
