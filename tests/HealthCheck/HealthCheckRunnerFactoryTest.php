<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck;

use App\HealthCheck\HealthCheckRunnerFactory;
use PHPUnit\Framework\TestCase;

/**
 * forDomain() itself wires up live network checks against a PDO-backed
 * HealthCheckRepository and isn't unit-tested here (no DB in this suite —
 * see CLAUDE.md). This covers the one pure decision it makes: which DKIM
 * selectors to probe.
 */
final class HealthCheckRunnerFactoryTest extends TestCase
{
    public function testDedupesOverlappingConfiguredAndObservedSelectors(): void
    {
        $merged = HealthCheckRunnerFactory::mergeSelectors(['default', 'google'], ['google', 'selector1']);

        self::assertSame(['default', 'google', 'selector1'], $merged);
    }

    public function testConfiguredSelectorsAloneWhenNoneObservedYet(): void
    {
        self::assertSame(['default'], HealthCheckRunnerFactory::mergeSelectors(['default'], []));
    }

    public function testObservedSelectorsAloneWhenNoneConfigured(): void
    {
        self::assertSame(['selector1'], HealthCheckRunnerFactory::mergeSelectors([], ['selector1']));
    }

    public function testEmptyWhenNeitherSourceHasSelectors(): void
    {
        self::assertSame([], HealthCheckRunnerFactory::mergeSelectors([], []));
    }
}
