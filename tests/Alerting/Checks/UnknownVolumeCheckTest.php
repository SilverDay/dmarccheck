<?php

declare(strict_types=1);

namespace App\Tests\Alerting\Checks;

use App\Alerting\Checks\UnknownVolumeCheck;
use App\Alerting\UnknownIpVolume;
use App\Tests\Alerting\ContextFactory;
use PHPUnit\Framework\TestCase;

final class UnknownVolumeCheckTest extends TestCase
{
    public function testFiresForAnIpOverTheThreshold(): void
    {
        $context = ContextFactory::make(unknownIpVolumes: [new UnknownIpVolume('203.0.113.5', 51)]);

        $findings = (new UnknownVolumeCheck(50))->evaluate($context);

        self::assertCount(1, $findings);
        self::assertSame('unknown_volume', $findings[0]->type);
        self::assertSame('203.0.113.5', $findings[0]->evidence['ip']);
    }

    public function testStaysSilentAtOrBelowTheThreshold(): void
    {
        $context = ContextFactory::make(unknownIpVolumes: [new UnknownIpVolume('203.0.113.5', 50)]);

        self::assertSame([], (new UnknownVolumeCheck(50))->evaluate($context));
    }

    public function testReturnsOneFindingPerOffendingIp(): void
    {
        $context = ContextFactory::make(unknownIpVolumes: [
            new UnknownIpVolume('203.0.113.5', 100),
            new UnknownIpVolume('203.0.113.6', 10),
            new UnknownIpVolume('203.0.113.7', 200),
        ]);

        self::assertCount(2, (new UnknownVolumeCheck(50))->evaluate($context));
    }
}
