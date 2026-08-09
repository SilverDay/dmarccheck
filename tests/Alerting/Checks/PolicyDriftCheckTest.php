<?php

declare(strict_types=1);

namespace App\Tests\Alerting\Checks;

use App\Alerting\Checks\PolicyDriftCheck;
use App\Tests\Alerting\ContextFactory;
use PHPUnit\Framework\TestCase;

final class PolicyDriftCheckTest extends TestCase
{
    public function testFiresOnDriftFromApprovedBaseline(): void
    {
        $context = ContextFactory::make(
            currentPublishedPolicy: 'p=quarantine',
            approvedBaselinePolicy: 'p=reject; sp=reject',
        );

        $findings = (new PolicyDriftCheck())->evaluate($context);

        self::assertCount(1, $findings);
        self::assertSame('policy_drift', $findings[0]->type);
    }

    public function testDoesNotFireWhenMatchingBaselineDespiteWhitespaceDifferences(): void
    {
        $context = ContextFactory::make(
            currentPublishedPolicy: 'p=reject;sp=reject',
            approvedBaselinePolicy: 'p=reject; sp=reject',
        );

        self::assertSame([], (new PolicyDriftCheck())->evaluate($context));
    }

    public function testStaysSilentWhenNoBaselineHasBeenApproved(): void
    {
        $context = ContextFactory::make(currentPublishedPolicy: 'p=quarantine', approvedBaselinePolicy: null);

        self::assertSame([], (new PolicyDriftCheck())->evaluate($context));
    }
}
