<?php

declare(strict_types=1);

namespace App\Tests\Recommendation;

use App\Recommendation\Rules\R3Rule;
use PHPUnit\Framework\TestCase;

final class R3RuleTest extends TestCase
{
    public function testFiresForSpfAlignmentIssue(): void
    {
        $stat     = SourceStatFactory::make(knownLabel: 'Corporate relay', spfOnlyFailCount: 5, spfAlignmentIssue: true);
        $findings = (new R3Rule())->evaluate(ContextFactory::make(standardStats: [$stat]));

        self::assertCount(1, $findings);
        self::assertSame(['spf'], $findings[0]->evidence['misaligned_mechanisms']);
    }

    public function testFiresForDkimAlignmentIssue(): void
    {
        $stat     = SourceStatFactory::make(knownLabel: 'Corporate relay', dkimOnlyFailCount: 5, dkimAlignmentIssue: true);
        $findings = (new R3Rule())->evaluate(ContextFactory::make(standardStats: [$stat]));

        self::assertCount(1, $findings);
        self::assertSame(['dkim'], $findings[0]->evidence['misaligned_mechanisms']);
    }

    public function testDoesNotFireForUnknownSender(): void
    {
        $stat     = SourceStatFactory::make(knownLabel: null, spfOnlyFailCount: 5, spfAlignmentIssue: true);
        $findings = (new R3Rule())->evaluate(ContextFactory::make(standardStats: [$stat]));

        self::assertSame([], $findings);
    }

    public function testDoesNotFireWithoutAnAlignmentIssue(): void
    {
        $stat     = SourceStatFactory::make(knownLabel: 'Corporate relay', spfOnlyFailCount: 5);
        $findings = (new R3Rule())->evaluate(ContextFactory::make(standardStats: [$stat]));

        self::assertSame([], $findings);
    }
}
