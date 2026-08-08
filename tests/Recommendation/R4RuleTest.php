<?php

declare(strict_types=1);

namespace App\Tests\Recommendation;

use App\Recommendation\Rules\R4Rule;
use PHPUnit\Framework\TestCase;

final class R4RuleTest extends TestCase
{
    public function testFiresWhenLookupCountExceedsLimit(): void
    {
        $findings = (new R4Rule())->evaluate(ContextFactory::make(spfLiveLookupCount: 11));

        self::assertCount(1, $findings);
        self::assertSame('R4', $findings[0]->ruleId);
        self::assertNull($findings[0]->subject);
    }

    public function testDoesNotFireAtOrBelowLimit(): void
    {
        self::assertSame([], (new R4Rule())->evaluate(ContextFactory::make(spfLiveLookupCount: 10)));
    }

    public function testDoesNotFireWhenLookupCountUnavailable(): void
    {
        self::assertSame([], (new R4Rule())->evaluate(ContextFactory::make(spfLiveLookupCount: null)));
    }
}
