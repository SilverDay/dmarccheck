<?php

declare(strict_types=1);

namespace App\Tests\Alerting\Checks;

use App\Alerting\Checks\PassRateRegressionCheck;
use App\Tests\Alerting\ContextFactory;
use PHPUnit\Framework\TestCase;

final class PassRateRegressionCheckTest extends TestCase
{
    public function testFiresOnADropPastTheThreshold(): void
    {
        $context = ContextFactory::make(
            recentTotalCount: 100,
            recentPassRatePct: 80.0,
            baselineTotalCount: 3000,
            baselinePassRatePct: 99.0,
        );

        $findings = (new PassRateRegressionCheck(10.0, 50))->evaluate($context);

        self::assertCount(1, $findings);
        self::assertSame('pass_rate_regression', $findings[0]->type);
    }

    public function testStaysSilentWhenDropIsAtOrBelowThreshold(): void
    {
        $context = ContextFactory::make(recentPassRatePct: 90.0, baselinePassRatePct: 99.0);

        self::assertSame([], (new PassRateRegressionCheck(9.0, 50))->evaluate($context));
    }

    public function testStaysSilentWhenRecentSampleIsTooSmall(): void
    {
        $context = ContextFactory::make(recentTotalCount: 5, recentPassRatePct: 10.0, baselinePassRatePct: 99.0);

        self::assertSame([], (new PassRateRegressionCheck(10.0, 50))->evaluate($context));
    }

    public function testStaysSilentWhenBaselineSampleIsTooSmall(): void
    {
        $context = ContextFactory::make(baselineTotalCount: 5, recentPassRatePct: 10.0, baselinePassRatePct: 99.0);

        self::assertSame([], (new PassRateRegressionCheck(10.0, 50))->evaluate($context));
    }

    public function testStaysSilentWithoutABaselineRate(): void
    {
        $context = ContextFactory::make(baselineTotalCount: 0, baselinePassRatePct: null);

        self::assertSame([], (new PassRateRegressionCheck(10.0, 50))->evaluate($context));
    }
}
