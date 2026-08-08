<?php

declare(strict_types=1);

namespace App\Tests\Auth;

use App\Auth\PasswordHasher;
use PHPUnit\Framework\TestCase;

final class PasswordHasherTest extends TestCase
{
    public function testHashVerifiesAgainstOriginalPassword(): void
    {
        $hasher = new PasswordHasher();
        $hash   = $hasher->hash('correct horse battery staple');

        self::assertTrue($hasher->verify('correct horse battery staple', $hash));
        self::assertFalse($hasher->verify('wrong password entirely', $hash));
    }

    public function testHashIsNotThePlaintext(): void
    {
        $hasher = new PasswordHasher();
        self::assertNotSame('correct horse battery staple', $hasher->hash('correct horse battery staple'));
    }

    public function testLengthPolicy(): void
    {
        $hasher = new PasswordHasher();

        self::assertFalse($hasher->meetsLengthPolicy('short'));
        self::assertTrue($hasher->meetsLengthPolicy('a-reasonably-long-password'));
        self::assertFalse($hasher->meetsLengthPolicy(str_repeat('a', PasswordHasher::MAX_LENGTH + 1)));
    }
}
