<?php

declare(strict_types=1);

namespace App\Tests\Recommendation;

use App\Recommendation\Rules\R11Rule;
use PHPUnit\Framework\TestCase;

final class R11RuleTest extends TestCase
{
    public function testFiresWhenSpUnsetAndSubdomainSpoofingObserved(): void
    {
        $stat    = SourceStatFactory::make(bothFailedCount: 1, headerFromDomains: ['evil.example.com']);
        $context = ContextFactory::make(
            domain: 'example.com',
            currentPublishedPolicy: 'p=reject',
            standardStats: [$stat],
        );

        $findings = (new R11Rule())->evaluate($context);

        self::assertCount(1, $findings);
        self::assertSame(['evil.example.com'], $findings[0]->evidence['subdomains']);
    }

    public function testDoesNotFireWhenSpAlreadySet(): void
    {
        $stat    = SourceStatFactory::make(bothFailedCount: 1, headerFromDomains: ['evil.example.com']);
        $context = ContextFactory::make(
            domain: 'example.com',
            currentPublishedPolicy: 'p=reject; sp=reject',
            standardStats: [$stat],
        );

        self::assertSame([], (new R11Rule())->evaluate($context));
    }

    public function testDoesNotFireForTheApexDomainItself(): void
    {
        $stat    = SourceStatFactory::make(bothFailedCount: 1, headerFromDomains: ['example.com']);
        $context = ContextFactory::make(
            domain: 'example.com',
            currentPublishedPolicy: 'p=reject',
            standardStats: [$stat],
        );

        self::assertSame([], (new R11Rule())->evaluate($context));
    }

    public function testDoesNotFireWithoutATotalFailure(): void
    {
        $stat    = SourceStatFactory::make(bothFailedCount: 0, headerFromDomains: ['evil.example.com']);
        $context = ContextFactory::make(
            domain: 'example.com',
            currentPublishedPolicy: 'p=reject',
            standardStats: [$stat],
        );

        self::assertSame([], (new R11Rule())->evaluate($context));
    }
}
