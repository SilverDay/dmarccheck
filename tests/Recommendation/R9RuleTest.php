<?php

declare(strict_types=1);

namespace App\Tests\Recommendation;

use App\Recommendation\Rules\R9Rule;
use PHPUnit\Framework\TestCase;

final class R9RuleTest extends TestCase
{
    public function testFiresOnDriftFromApprovedBaseline(): void
    {
        $context = ContextFactory::make(
            currentPublishedPolicy: 'p=quarantine',
            approvedBaselinePolicy: 'p=reject; sp=reject',
        );

        $findings = (new R9Rule())->evaluate($context);

        self::assertCount(1, $findings);
        self::assertSame('R9', $findings[0]->ruleId);
        self::assertSame('high', $findings[0]->severity);
    }

    public function testDoesNotFireWhenMatchingBaselineDespiteWhitespaceDifferences(): void
    {
        $context = ContextFactory::make(
            currentPublishedPolicy: 'p=reject;sp=reject',
            approvedBaselinePolicy: 'p=reject; sp=reject',
        );

        self::assertSame([], (new R9Rule())->evaluate($context));
    }

    public function testStaysSilentWhenNoBaselineHasBeenApproved(): void
    {
        $context = ContextFactory::make(currentPublishedPolicy: 'p=quarantine', approvedBaselinePolicy: null);

        self::assertSame([], (new R9Rule())->evaluate($context));
    }
}
