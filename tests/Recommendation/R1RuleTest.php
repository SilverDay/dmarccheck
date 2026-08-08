<?php

declare(strict_types=1);

namespace App\Tests\Recommendation;

use App\Recommendation\Rules\R1Rule;
use PHPUnit\Framework\TestCase;

final class R1RuleTest extends TestCase
{
    public function testFiresForCleanSpfFailureFromKnownSender(): void
    {
        $stat     = SourceStatFactory::make(knownLabel: 'Corporate relay', spfOnlyFailCount: 5);
        $findings = (new R1Rule())->evaluate(ContextFactory::make(standardStats: [$stat]));

        self::assertCount(1, $findings);
        self::assertSame('R1', $findings[0]->ruleId);
        self::assertSame($stat->ip, $findings[0]->subject);
    }

    public function testDoesNotFireForUnknownSender(): void
    {
        $stat     = SourceStatFactory::make(knownLabel: null, spfOnlyFailCount: 5);
        $findings = (new R1Rule())->evaluate(ContextFactory::make(standardStats: [$stat]));

        self::assertSame([], $findings);
    }

    public function testDoesNotFireForKnownForwarder(): void
    {
        $stat     = SourceStatFactory::make(knownLabel: 'Known forwarder', spfOnlyFailCount: 5);
        $findings = (new R1Rule())->evaluate(ContextFactory::make(standardStats: [$stat]));

        self::assertSame([], $findings, 'forwarder-shaped failures route to R12, not R1');
    }

    public function testDoesNotFireWhenItsAnAlignmentIssue(): void
    {
        $stat     = SourceStatFactory::make(knownLabel: 'Corporate relay', spfOnlyFailCount: 5, spfAlignmentIssue: true);
        $findings = (new R1Rule())->evaluate(ContextFactory::make(standardStats: [$stat]));

        self::assertSame([], $findings, 'alignment issues route to R3, not R1');
    }
}
