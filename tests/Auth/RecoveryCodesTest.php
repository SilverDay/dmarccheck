<?php

declare(strict_types=1);

namespace App\Tests\Auth;

use App\Auth\RecoveryCodes;
use PHPUnit\Framework\TestCase;

final class RecoveryCodesTest extends TestCase
{
    public function testGenerateSetProducesTheRequestedCountOfUniqueCodes(): void
    {
        $codes = (new RecoveryCodes())->generateSet(10);

        self::assertCount(10, $codes);
        self::assertCount(10, array_unique($codes));

        foreach ($codes as $code) {
            self::assertMatchesRegularExpression('/^[A-Z2-9]{5}-[A-Z2-9]{5}$/', $code);
        }
    }

    public function testFindMatchLocatesTheCorrectUnconsumedRow(): void
    {
        $recoveryCodes = new RecoveryCodes();
        $plain         = $recoveryCodes->generateSet(3);

        $rows = [];
        foreach ($plain as $i => $code) {
            $rows[] = ['id' => $i + 1, 'code_hash' => $recoveryCodes->hash($code), 'consumed_at' => null];
        }

        $matchId = $recoveryCodes->findMatch($rows, $plain[1]);

        self::assertSame(2, $matchId);
    }

    public function testFindMatchIsCaseInsensitiveAndTrims(): void
    {
        $recoveryCodes = new RecoveryCodes();
        $plain         = $recoveryCodes->generateSet(1)[0];
        $rows          = [['id' => 1, 'code_hash' => $recoveryCodes->hash($plain), 'consumed_at' => null]];

        self::assertSame(1, $recoveryCodes->findMatch($rows, ' ' . strtolower($plain) . ' '));
    }

    public function testFindMatchIgnoresConsumedRows(): void
    {
        $recoveryCodes = new RecoveryCodes();
        $plain         = $recoveryCodes->generateSet(1)[0];
        $rows          = [['id' => 1, 'code_hash' => $recoveryCodes->hash($plain), 'consumed_at' => '2026-01-01 00:00:00']];

        self::assertNull($recoveryCodes->findMatch($rows, $plain));
    }

    public function testFindMatchReturnsNullForUnknownCode(): void
    {
        $recoveryCodes = new RecoveryCodes();
        $rows          = [['id' => 1, 'code_hash' => $recoveryCodes->hash('AAAAA-BBBBB'), 'consumed_at' => null]];

        self::assertNull($recoveryCodes->findMatch($rows, 'ZZZZZ-ZZZZZ'));
    }
}
