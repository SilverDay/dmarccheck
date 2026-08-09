<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck\Fix;

use App\HealthCheck\Fix\SpfFixSuggester;
use PHPUnit\Framework\TestCase;

final class SpfFixSuggesterTest extends TestCase
{
    public function testNoRecordSuggestsAFreshMinimalOne(): void
    {
        $fixes = SpfFixSuggester::suggest('example.com', ['reason' => 'no SPF record found']);

        self::assertCount(1, $fixes);
        self::assertSame('example.com', $fixes[0]->recordName);
        self::assertSame('v=spf1 mx -all', $fixes[0]->recordValue);
    }

    public function testOpenAllIsCorrectedToHardFailPreservingOtherMechanisms(): void
    {
        $fixes = SpfFixSuggester::suggest('example.com', [
            'record'       => 'v=spf1 mx include:_spf.google.com +all',
            'lookup_count' => 2,
            'issues'       => ["'+all' publishes an open, unrestricted SPF result — treat as a critical misconfiguration"],
        ]);

        self::assertCount(1, $fixes);
        self::assertSame('v=spf1 mx include:_spf.google.com -all', $fixes[0]->recordValue);
    }

    public function testMissingAllMechanismGetsAConservativeSoftfailAppended(): void
    {
        $fixes = SpfFixSuggester::suggest('example.com', [
            'record'       => 'v=spf1 mx',
            'lookup_count' => 1,
            'issues'       => ["no 'all' mechanism — non-matching senders get an implicit neutral result"],
        ]);

        self::assertCount(1, $fixes);
        self::assertSame('v=spf1 mx ~all', $fixes[0]->recordValue);
    }

    public function testAnAlreadySetSoftfailIsLeftAlone(): void
    {
        $fixes = SpfFixSuggester::suggest('example.com', [
            'record'       => 'v=spf1 mx ~all',
            'lookup_count' => 1,
            'issues'       => ["'~all' is a weak/neutral catch-all qualifier"],
        ]);

        self::assertSame([], $fixes);
    }

    public function testAnAlreadyCleanHardFailRecordHasNoSuggestion(): void
    {
        $fixes = SpfFixSuggester::suggest('example.com', [
            'record'       => 'v=spf1 mx -all',
            'lookup_count' => 1,
            'issues'       => [],
        ]);

        self::assertSame([], $fixes);
    }

    public function testMultipleRecordsIsNotAutoFixable(): void
    {
        $fixes = SpfFixSuggester::suggest('example.com', [
            'reason'  => 'multiple SPF records published (RFC 7208 permerror)',
            'records' => ['v=spf1 -all', 'v=spf1 mx -all'],
        ]);

        self::assertSame([], $fixes);
    }

    public function testLookupLimitExceededWithAnAlreadyCorrectAllIsNotAutoFixable(): void
    {
        $fixes = SpfFixSuggester::suggest('example.com', [
            'record'       => 'v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com include:i.com include:j.com include:k.com -all',
            'lookup_count' => 11,
            'issues'       => ['DNS-lookup mechanisms (11) exceed the RFC 7208 limit of 10 (permerror)'],
        ]);

        self::assertSame([], $fixes);
    }
}
