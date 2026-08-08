<?php

declare(strict_types=1);

namespace App\Tests\Recommendation;

use App\Recommendation\Rules\R5Rule;
use PHPUnit\Framework\TestCase;

final class R5RuleTest extends TestCase
{
    public function testFiresForUnknownSourceOverThreshold(): void
    {
        $stat     = SourceStatFactory::make(knownLabel: null, bothFailedCount: 51);
        $findings = (new R5Rule(50))->evaluate(ContextFactory::make(standardStats: [$stat]));

        self::assertCount(1, $findings);
        self::assertSame('R5', $findings[0]->ruleId);
        self::assertSame('high', $findings[0]->severity);
    }

    public function testDoesNotFireAtOrBelowThreshold(): void
    {
        $stat = SourceStatFactory::make(knownLabel: null, bothFailedCount: 50);

        self::assertSame([], (new R5Rule(50))->evaluate(ContextFactory::make(standardStats: [$stat])));
    }

    public function testDoesNotFireForKnownSender(): void
    {
        $stat = SourceStatFactory::make(knownLabel: 'Corporate relay', bothFailedCount: 100);

        self::assertSame([], (new R5Rule(50))->evaluate(ContextFactory::make(standardStats: [$stat])));
    }
}
