<?php

declare(strict_types=1);

namespace App\Tests\Http\Controllers;

use App\Http\Controllers\DomainController;
use PHPUnit\Framework\TestCase;

/**
 * DomainController::add()/approveBaseline() are PDO/health-check
 * orchestration and aren't unit-tested here (no DB in this suite — see
 * CLAUDE.md), same as HealthCheckRepository/RecommendationRepository.
 * This covers the one pure decision approveBaseline() makes, extracted so
 * it's callable without constructing the controller (which needs a PDO).
 */
final class DomainControllerTest extends TestCase
{
    public function testNoObservedPolicyIsNotApprovable(): void
    {
        self::assertNull(DomainController::approvableBaseline(null));
    }

    public function testAnObservedPolicyIsApprovableAsIs(): void
    {
        self::assertSame('reject', DomainController::approvableBaseline('reject'));
        self::assertSame('quarantine', DomainController::approvableBaseline('quarantine'));
        self::assertSame('none', DomainController::approvableBaseline('none'));
    }
}
