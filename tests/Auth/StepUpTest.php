<?php

declare(strict_types=1);

namespace App\Tests\Auth;

use App\Auth\StepUp;
use PHPUnit\Framework\TestCase;

final class StepUpTest extends TestCase
{
    public function testAcceptsSameOriginRelativePaths(): void
    {
        self::assertSame('/domain?domain=example.com', StepUp::sanitizeReturnTo('/domain?domain=example.com'));
        self::assertSame('/admin/users', StepUp::sanitizeReturnTo('/admin/users'));
        self::assertSame('/', StepUp::sanitizeReturnTo('/'));
    }

    public function testFallsBackToSlashWhenMissing(): void
    {
        self::assertSame('/', StepUp::sanitizeReturnTo(null));
        self::assertSame('/', StepUp::sanitizeReturnTo(''));
    }

    public function testRejectsOpenRedirectPayloads(): void
    {
        self::assertSame('/', StepUp::sanitizeReturnTo('//evil.example/phish'));
        self::assertSame('/', StepUp::sanitizeReturnTo('https://evil.example/'));
        self::assertSame('/', StepUp::sanitizeReturnTo('http://evil.example/'));
        self::assertSame('/', StepUp::sanitizeReturnTo('javascript:alert(1)'));
        self::assertSame('/', StepUp::sanitizeReturnTo('not-a-path'));
    }
}
