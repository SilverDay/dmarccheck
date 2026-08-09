<?php

declare(strict_types=1);

namespace App\Tests\Http\Controllers;

use App\Http\Controllers\DomainController;
use PHPUnit\Framework\TestCase;

/**
 * DomainController::add()/approveBaseline()/updatePolicy()/deactivate()/
 * reactivate() are PDO/health-check orchestration and aren't unit-tested
 * here (no DB in this suite — see CLAUDE.md), same as
 * HealthCheckRepository/RecommendationRepository. This covers the pure
 * decisions approveBaseline()/updatePolicy() make, extracted so they're
 * callable without constructing the controller (which needs a PDO).
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

    public function testComposesAValidTargetPolicy(): void
    {
        self::assertSame('p=reject; sp=reject', DomainController::composeTargetPolicy('reject', 'reject'));
        self::assertSame('p=none; sp=quarantine', DomainController::composeTargetPolicy('none', 'quarantine'));
    }

    public function testNormalizesCaseAndWhitespaceBeforeComposing(): void
    {
        self::assertSame('p=reject; sp=none', DomainController::composeTargetPolicy(' REJECT ', 'None'));
    }

    public function testRejectsAnInvalidPValue(): void
    {
        self::assertNull(DomainController::composeTargetPolicy('bogus', 'reject'));
    }

    public function testRejectsAnInvalidSpValue(): void
    {
        self::assertNull(DomainController::composeTargetPolicy('reject', 'bogus'));
    }

    public function testRejectsEmptyValues(): void
    {
        self::assertNull(DomainController::composeTargetPolicy('', ''));
    }
}
