<?php

declare(strict_types=1);

namespace App\Tests\Recommendation;

use App\Recommendation\PolicyLevel;
use PHPUnit\Framework\TestCase;

/**
 * Scoped to isValidLevel()/compose() only — the pre-existing
 * extract()/extractSubdomainPolicy()/isStricter()/normalize() have no
 * direct test coverage and aren't backfilled here.
 */
final class PolicyLevelTest extends TestCase
{
    public function testValidLevelsAreAccepted(): void
    {
        self::assertTrue(PolicyLevel::isValidLevel('none'));
        self::assertTrue(PolicyLevel::isValidLevel('quarantine'));
        self::assertTrue(PolicyLevel::isValidLevel('reject'));
    }

    public function testInvalidOrUnnormalizedInputIsRejected(): void
    {
        self::assertFalse(PolicyLevel::isValidLevel(''));
        self::assertFalse(PolicyLevel::isValidLevel('bogus'));
        self::assertFalse(PolicyLevel::isValidLevel('REJECT'));
    }

    public function testComposeFormatsBothTags(): void
    {
        self::assertSame('p=none; sp=reject', PolicyLevel::compose('none', 'reject'));
    }
}
