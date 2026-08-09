<?php

declare(strict_types=1);

namespace App\Tests\Auth;

use App\Auth\AuthUser;
use App\Auth\PasswordHasher;
use App\Auth\SealedCookie;
use App\Auth\StepUp;
use PHPUnit\Framework\TestCase;

final class StepUpTest extends TestCase
{
    public function testFormAttrMarksPasskeyOnlyActorsForTransparentSubmitTimeCeremony(): void
    {
        $stepUp = new StepUp(new PasswordHasher(), new SealedCookie('secret', true));

        self::assertSame(' data-step-up-passkey', $stepUp->formAttr($this->makeUser(credentialHash: null)));
        self::assertSame('', $stepUp->formAttr($this->makeUser(credentialHash: 'hash')));
    }

    public function testFieldHtmlGivesPasswordActorsAnInlinePasswordFieldAndPasskeyActorsAnErrorSlotOnly(): void
    {
        $stepUp = new StepUp(new PasswordHasher(), new SealedCookie('secret', true));

        $passkeyOnly = $stepUp->fieldHtml($this->makeUser(credentialHash: null));
        self::assertStringNotContainsString('<input type="password"', $passkeyOnly);
        self::assertStringContainsString('step-up-error', $passkeyOnly);

        $passwordActor = $stepUp->fieldHtml($this->makeUser(credentialHash: 'hash'));
        self::assertStringContainsString('<input type="password" name="current_password" required>', $passwordActor);
    }

    private function makeUser(?string $credentialHash): AuthUser
    {
        return new AuthUser(1, 'user@example.com', $credentialHash, null, 'admin', 'active', new \DateTimeImmutable(), null);
    }
}
