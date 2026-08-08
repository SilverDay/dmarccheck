<?php

declare(strict_types=1);

namespace App\Auth;

/**
 * Three global roles (spec §15.1), clean and non-overlapping:
 * read_only ⊂ admin ⊂ super_admin.
 */
final class Roles
{
    public const string READ_ONLY   = 'read_only';
    public const string ADMIN       = 'admin';
    public const string SUPER_ADMIN = 'super_admin';

    /** @var array<string, int> */
    private const array RANK = [
        self::READ_ONLY   => 0,
        self::ADMIN       => 1,
        self::SUPER_ADMIN => 2,
    ];

    public static function isValid(string $role): bool
    {
        return isset(self::RANK[$role]);
    }

    /** True when $role has at least the privilege of $min. */
    public static function atLeast(string $role, string $min): bool
    {
        return (self::RANK[$role] ?? -1) >= (self::RANK[$min] ?? PHP_INT_MAX);
    }
}
