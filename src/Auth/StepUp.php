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

    /**
     * $returnTo is where the browser lands after a successful passkey
     * ceremony (see sanitizeReturnTo()) — the page this field is rendered
     * on, so re-verifying reloads the actor right back to the pending
     * action instead of detouring through /account/security.
     */
    public function fieldHtml(AuthUser $actor, string $returnTo): string
    {
        if (!$actor->hasPassword()) {
            return '<p class="step-up-field">'
                . '<span class="step-up-hint">Passkey-only account —</span>'
                . '<input type="hidden" name="return_to" value="' . htmlspecialchars($returnTo, ENT_QUOTES, 'UTF-8') . '">'
                . '<button type="button" class="btn btn-secondary btn-sm" data-webauthn="authenticate"'
                . ' data-options-url="/account/stepup/passkey/options" data-verify-url="/account/stepup/passkey/verify"'
                . ' data-extra-fields="return_to">Verify with passkey</button>'
                . '<span class="step-up-error error"></span>'
                . '</p>';
        }

        return '<p class="step-up-field"><label>Current password'
            . '<input type="password" name="current_password" required></label></p>';
    }

    /**
     * Same-origin relative-path allowlist for the passkey ceremony's
     * post-verify redirect (spec §15.4) — the value round-trips through an
     * unauthenticated-until-verified POST body, so it must never be able to
     * send the browser off-site (open redirect) via a "//host" or absolute
     * URL payload.
     */
    public static function sanitizeReturnTo(?string $returnTo): string
    {
        if ($returnTo === null || $returnTo === '' || preg_match('#^/(?!/)[A-Za-z0-9\-._~!$&\'()*+,;=:@/%?]*$#', $returnTo) !== 1) {
            return '/';
        }

        return $returnTo;
    }
}
