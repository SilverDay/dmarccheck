<?php

declare(strict_types=1);

namespace App\Tests\Recommendation;

use App\Recommendation\Rules\R7Rule;
use PHPUnit\Framework\TestCase;

final class R7RuleTest extends TestCase
{
    public function testFiresWhenAtNoneWithNoKnownFailuresAndStricterTarget(): void
    {
        $context = ContextFactory::make(
            currentPublishedPolicy: 'p=none',
            targetPolicy: 'p=reject; sp=reject',
        );

        $findings = (new R7Rule())->evaluate($context);

        self::assertCount(1, $findings);
        self::assertSame('R7', $findings[0]->ruleId);
    }

    public function testUsesTheConfiguredQuarantineTargetWithoutTreatingPctAsTheTarget(): void
    {
        $context = ContextFactory::make(
            currentPublishedPolicy: 'p=none; pct=50; t=y',
            targetPolicy: 'p=quarantine',
        );

        $findings = (new R7Rule())->evaluate($context);

        self::assertCount(1, $findings);
        self::assertSame('p=none; pct=50; t=y', $findings[0]->evidence['current_policy']);
        self::assertSame('p=quarantine', $findings[0]->evidence['target_policy']);
    }

    public function testDoesNotFireWhenAKnownSenderIsFailing(): void
    {
        $stat    = SourceStatFactory::make(knownLabel: 'Corporate relay', bothFailedCount: 1);
        $context = ContextFactory::make(
            currentPublishedPolicy: 'p=none',
            targetPolicy: 'p=reject',
            standardStats: [$stat],
        );

        self::assertSame([], (new R7Rule())->evaluate($context));
    }

    public function testDoesNotFireWhenNotAtNone(): void
    {
        $context = ContextFactory::make(currentPublishedPolicy: 'p=quarantine', targetPolicy: 'p=reject');

        self::assertSame([], (new R7Rule())->evaluate($context));
    }

    public function testDoesNotFireWhenTargetIsNotStricter(): void
    {
        $context = ContextFactory::make(currentPublishedPolicy: 'p=none', targetPolicy: 'p=none');

        self::assertSame([], (new R7Rule())->evaluate($context));
    }
}
