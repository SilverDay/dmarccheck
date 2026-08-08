<?php

declare(strict_types=1);

namespace App\Tests\Auth;

use App\Auth\Roles;
use PHPUnit\Framework\TestCase;

final class RolesTest extends TestCase
{
    public function testHierarchyIsCumulative(): void
    {
        self::assertTrue(Roles::atLeast(Roles::SUPER_ADMIN, Roles::READ_ONLY));
        self::assertTrue(Roles::atLeast(Roles::SUPER_ADMIN, Roles::ADMIN));
        self::assertTrue(Roles::atLeast(Roles::SUPER_ADMIN, Roles::SUPER_ADMIN));
        self::assertTrue(Roles::atLeast(Roles::ADMIN, Roles::READ_ONLY));
    }

    public function testLowerRoleDoesNotSatisfyHigherRequirement(): void
    {
        self::assertFalse(Roles::atLeast(Roles::READ_ONLY, Roles::ADMIN));
        self::assertFalse(Roles::atLeast(Roles::READ_ONLY, Roles::SUPER_ADMIN));
        self::assertFalse(Roles::atLeast(Roles::ADMIN, Roles::SUPER_ADMIN));
    }

    public function testUnknownRoleSatisfiesNothing(): void
    {
        self::assertFalse(Roles::atLeast('bogus', Roles::READ_ONLY));
    }

    public function testIsValid(): void
    {
        self::assertTrue(Roles::isValid(Roles::ADMIN));
        self::assertFalse(Roles::isValid('bogus'));
    }
}
