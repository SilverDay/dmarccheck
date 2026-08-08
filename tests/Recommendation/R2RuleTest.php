<?php

declare(strict_types=1);

namespace App\Tests\Recommendation;

use App\Recommendation\Rules\R2Rule;
use PHPUnit\Framework\TestCase;

final class R2RuleTest extends TestCase
{
    public function testFiresForCleanDkimFailureFromKnownSender(): void
    {
        $stat     = SourceStatFactory::make(knownLabel: 'Corporate relay', dkimOnlyFailCount: 3);
        $findings = (new R2Rule())->evaluate(ContextFactory::make(standardStats: [$stat]));

        self::assertCount(1, $findings);
        self::assertSame('R2', $findings[0]->ruleId);
    }

    public function testDoesNotFireWhenItsAnAlignmentIssue(): void
    {
        $stat     = SourceStatFactory::make(knownLabel: 'Corporate relay', dkimOnlyFailCount: 3, dkimAlignmentIssue: true);
        $findings = (new R2Rule())->evaluate(ContextFactory::make(standardStats: [$stat]));

        self::assertSame([], $findings);
    }

    public function testDoesNotFireForUnknownSender(): void
    {
        $stat     = SourceStatFactory::make(knownLabel: null, dkimOnlyFailCount: 3);
        $findings = (new R2Rule())->evaluate(ContextFactory::make(standardStats: [$stat]));

        self::assertSame([], $findings);
    }
}
