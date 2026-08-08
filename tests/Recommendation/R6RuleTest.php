<?php

declare(strict_types=1);

namespace App\Tests\Recommendation;

use App\Recommendation\Rules\R6Rule;
use PHPUnit\Framework\TestCase;

final class R6RuleTest extends TestCase
{
    public function testFiresWhenSustainedAcrossEnoughDistinctDays(): void
    {
        $stat    = SourceStatFactory::make(knownLabel: null, bothFailedCount: 51, distinctReportDays: 3);
        $context = ContextFactory::make(sustainedStats: [$stat], sustainedMinDays: 3);

        $findings = (new R6Rule(50))->evaluate($context);

        self::assertCount(1, $findings);
        self::assertSame('R6', $findings[0]->ruleId);
    }

    public function testDoesNotFireWhenNotSustained(): void
    {
        $stat    = SourceStatFactory::make(knownLabel: null, bothFailedCount: 51, distinctReportDays: 1);
        $context = ContextFactory::make(sustainedStats: [$stat], sustainedMinDays: 3);

        self::assertSame([], (new R6Rule(50))->evaluate($context));
    }

    public function testDoesNotFireBelowVolumeThresholdEvenIfSustained(): void
    {
        $stat    = SourceStatFactory::make(knownLabel: null, bothFailedCount: 10, distinctReportDays: 5);
        $context = ContextFactory::make(sustainedStats: [$stat], sustainedMinDays: 3);

        self::assertSame([], (new R6Rule(50))->evaluate($context));
    }
}
