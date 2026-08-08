<?php

declare(strict_types=1);

namespace App\Auth;

/**
 * Verifier-side password hashing per NIST SP 800-63B (spec §15.3): Argon2id,
 * no composition rules, no forced rotation — those are policy decisions made
 * by *not* enforcing them here.
 */
final class PasswordHasher
{
    public const int MIN_LENGTH = 12;
    public const int MAX_LENGTH = 256;

    public function hash(string $password): string
    {
        return password_hash($password, PASSWORD_ARGON2ID);
    }

    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_ARGON2ID);
    }

    /** Length-only check; deliberately no composition rules (§15.3). */
    public function meetsLengthPolicy(string $password): bool
    {
        $length = mb_strlen($password);

        return $length >= self::MIN_LENGTH && $length <= self::MAX_LENGTH;
    }
}
