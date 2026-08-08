<?php

declare(strict_types=1);

namespace App\Tests\Auth;

use App\Auth\Csrf;
use PHPUnit\Framework\TestCase;

final class CsrfTest extends TestCase
{
    public function testTokenVerifiesForTheSameSession(): void
    {
        $csrf  = new Csrf('app-secret');
        $token = $csrf->token('session-token-a');

        self::assertTrue($csrf->verify('session-token-a', $token));
    }

    public function testTokenDoesNotVerifyForADifferentSession(): void
    {
        $csrf  = new Csrf('app-secret');
        $token = $csrf->token('session-token-a');

        self::assertFalse($csrf->verify('session-token-b', $token));
    }

    public function testDifferentAppSecretsProduceDifferentTokens(): void
    {
        $tokenA = (new Csrf('secret-a'))->token('session-token');
        $tokenB = (new Csrf('secret-b'))->token('session-token');

        self::assertNotSame($tokenA, $tokenB);
    }

    public function testGarbageSubmittedTokenFailsVerification(): void
    {
        $csrf = new Csrf('app-secret');
        self::assertFalse($csrf->verify('session-token-a', 'not-a-real-token'));
    }
}
