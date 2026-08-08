<?php

declare(strict_types=1);

namespace App\Tests\Recommendation;

use App\Recommendation\Rules\R8Rule;
use PHPUnit\Framework\TestCase;

final class R8RuleTest extends TestCase
{
    public function testFiresWhenAtQuarantineWithNoKnownFailuresAndStricterTarget(): void
    {
        $context = ContextFactory::make(currentPublishedPolicy: 'p=quarantine', targetPolicy: 'p=reject');

        $findings = (new R8Rule())->evaluate($context);

        self::assertCount(1, $findings);
        self::assertSame('R8', $findings[0]->ruleId);
    }

    public function testDoesNotFireWhenAKnownSenderIsFailing(): void
    {
        $stat    = SourceStatFactory::make(knownLabel: 'Corporate relay', bothFailedCount: 1);
        $context = ContextFactory::make(
            currentPublishedPolicy: 'p=quarantine',
            targetPolicy: 'p=reject',
            standardStats: [$stat],
        );

        self::assertSame([], (new R8Rule())->evaluate($context));
    }

    public function testDoesNotFireWhenNotAtQuarantine(): void
    {
        $context = ContextFactory::make(currentPublishedPolicy: 'p=none', targetPolicy: 'p=reject');

        self::assertSame([], (new R8Rule())->evaluate($context));
    }
}
