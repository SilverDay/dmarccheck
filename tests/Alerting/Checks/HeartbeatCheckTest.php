<?php

declare(strict_types=1);

namespace App\Tests\Alerting\Checks;

use App\Alerting\Checks\HeartbeatCheck;
use App\Tests\Alerting\ContextFactory;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class HeartbeatCheckTest extends TestCase
{
    public function testStaysSilentWhenReportsArriveRecently(): void
    {
        $context = ContextFactory::make(lastReportReceivedAt: new DateTimeImmutable('-1 hour'));

        self::assertSame([], (new HeartbeatCheck(3))->evaluate($context));
    }

    public function testFiresWhenNoReportsSinceBeforeTheHeartbeatWindow(): void
    {
        $context = ContextFactory::make(lastReportReceivedAt: new DateTimeImmutable('-5 days'));

        $findings = (new HeartbeatCheck(3))->evaluate($context);

        self::assertCount(1, $findings);
        self::assertSame('heartbeat', $findings[0]->type);
    }

    public function testFallsBackToDomainCreatedAtWhenNoReportsHaveEverArrived(): void
    {
        $context = ContextFactory::make(
            domainCreatedAt: new DateTimeImmutable('-10 days'),
            lastReportReceivedAt: null,
        );

        $findings = (new HeartbeatCheck(3))->evaluate($context);

        self::assertCount(1, $findings);
    }

    public function testStaysSilentForABrandNewDomainWithinTheGracePeriod(): void
    {
        $context = ContextFactory::make(
            domainCreatedAt: new DateTimeImmutable('-1 hour'),
            lastReportReceivedAt: null,
        );

        self::assertSame([], (new HeartbeatCheck(3))->evaluate($context));
    }
}
