<?php

declare(strict_types=1);

namespace App\Tests\Recommendation;

use App\Recommendation\Rules\R12Rule;
use PHPUnit\Framework\TestCase;

final class R12RuleTest extends TestCase
{
    public function testFiresForKnownForwarderWithSpfFailure(): void
    {
        $stat     = SourceStatFactory::make(knownLabel: 'Known forwarder — mailing list', spfOnlyFailCount: 4);
        $findings = (new R12Rule())->evaluate(ContextFactory::make(standardStats: [$stat]));

        self::assertCount(1, $findings);
        self::assertSame('R12', $findings[0]->ruleId);
        self::assertSame('info', $findings[0]->severity);
    }

    public function testDoesNotFireForNonForwarderKnownSender(): void
    {
        $stat = SourceStatFactory::make(knownLabel: 'Corporate relay', spfOnlyFailCount: 4);

        self::assertSame([], (new R12Rule())->evaluate(ContextFactory::make(standardStats: [$stat])));
    }

    public function testDoesNotFireWithoutAnSpfFailure(): void
    {
        $stat = SourceStatFactory::make(knownLabel: 'Known forwarder', spfOnlyFailCount: 0);

        self::assertSame([], (new R12Rule())->evaluate(ContextFactory::make(standardStats: [$stat])));
    }
}
