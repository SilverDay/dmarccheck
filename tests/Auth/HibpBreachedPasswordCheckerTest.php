<?php

declare(strict_types=1);

namespace App\Tests\Auth;

use App\Auth\HibpBreachedPasswordChecker;
use PHPUnit\Framework\TestCase;

/**
 * Scoped to matchesSuffix() only — the pure parsing half of a class whose
 * isBreached()/fetch() touch the network and aren't unit-tested here,
 * same convention as MtaStsCheck (no MtaStsCheckTest.php exists either).
 */
final class HibpBreachedPasswordCheckerTest extends TestCase
{
    public function testFindsASuffixInAMultiLineResponse(): void
    {
        $response = "003D68EB55068C33ACE09247EE4C639306:3\r\n"
            . "0090C6863E4451D0DE2008C425E830AA1F:4\r\n"
            . "AABBCCDDEEFF00112233445566778899AA:5";

        self::assertTrue(HibpBreachedPasswordChecker::matchesSuffix($response, 'AABBCCDDEEFF00112233445566778899AA'));
    }

    public function testReturnsFalseWhenSuffixIsAbsent(): void
    {
        $response = "003D68EB55068C33ACE09247EE4C639306:3\r\n0090C6863E4451D0DE2008C425E830AA1F:4";

        self::assertFalse(HibpBreachedPasswordChecker::matchesSuffix($response, 'DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEA'));
    }

    public function testReturnsFalseForAnEmptyResponse(): void
    {
        self::assertFalse(HibpBreachedPasswordChecker::matchesSuffix('', 'AABBCCDDEEFF00112233445566778899AA'));
        self::assertFalse(HibpBreachedPasswordChecker::matchesSuffix("   \n  ", 'AABBCCDDEEFF00112233445566778899AA'));
    }

    public function testHandlesBareNewlinesNotJustCrlf(): void
    {
        $response = "AAAA:1\nBBBB:2\nCCCC:3";

        self::assertTrue(HibpBreachedPasswordChecker::matchesSuffix($response, 'BBBB'));
    }

    public function testMatchIsCaseSensitive(): void
    {
        self::assertFalse(HibpBreachedPasswordChecker::matchesSuffix('aabbccdd:3', 'AABBCCDD'));
    }
}
