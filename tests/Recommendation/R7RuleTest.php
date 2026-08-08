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
