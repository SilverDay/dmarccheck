<?php

declare(strict_types=1);

namespace App\Tests\Recommendation;

use App\Recommendation\Rules\R10Rule;
use PHPUnit\Framework\TestCase;

final class R10RuleTest extends TestCase
{
    public function testFiresWhenNonSendingDomainHasRecords(): void
    {
        $stat    = SourceStatFactory::make(totalCount: 5);
        $context = ContextFactory::make(nonSending: true, standardStats: [$stat]);

        $findings = (new R10Rule())->evaluate($context);

        self::assertCount(1, $findings);
        self::assertSame('R10', $findings[0]->ruleId);
    }

    public function testDoesNotFireWhenNotFlaggedNonSending(): void
    {
        $stat    = SourceStatFactory::make(totalCount: 5);
        $context = ContextFactory::make(nonSending: false, standardStats: [$stat]);

        self::assertSame([], (new R10Rule())->evaluate($context));
    }

    public function testDoesNotFireWhenNoRecordsObserved(): void
    {
        $context = ContextFactory::make(nonSending: true, standardStats: []);

        self::assertSame([], (new R10Rule())->evaluate($context));
    }
}
