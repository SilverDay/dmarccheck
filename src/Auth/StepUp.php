<?php

declare(strict_types=1);

namespace App\Auth;

/**
 * Step-up re-authentication (spec §15.4/§15.5) for the currently
 * authenticated actor, shared between self-service (SecurityController)
 * and admin actions (AdminUsersController) — both need the same check: a
 * password user re-enters their current password with the request; a
 * passkey-only user instead does a fresh assertion first via
 * SecurityController's /account/stepup/passkey/* endpoints, which stamp
 * the "ok" cookie this class consumes (single use).
 */
final class StepUp
{
    private const string COOKIE_NAME = 'dmarc_ceremony';
    public const string PURPOSE_OK   = 'stepup_ok';

    public function __construct(
        private readonly PasswordHasher $hasher,
        private readonly SealedCookie $sealed,
    ) {
    }

    public function verify(AuthUser $actor): bool
    {
        if ($actor->hasPassword()) {
            $current = (string) ($_POST['current_password'] ?? '');

            return $this->hasher->verify($current, (string) $actor->credentialHash);
        }

        $pending = $this->sealed->readCookie(self::COOKIE_NAME, self::PURPOSE_OK);
        $this->sealed->clearCookie(self::COOKIE_NAME);

        return $pending !== null && (int) $pending['user_id'] === $actor->id;
    }

    public function fieldHtml(AuthUser $actor): string
    {
        if (!$actor->hasPassword()) {
            return '<p class="step-up-field"><em>Passkey-only account — <a href="/account/security">verify with your passkey</a> first, then retry.</em></p>';
        }

        return '<p class="step-up-field"><label>Current password'
            . '<input type="password" name="current_password" required></label></p>';
    }
}
