<?php

declare(strict_types=1);

namespace App\Auth;

/**
 * Step-up re-authentication (spec §15.4/§15.5) for the currently
 * authenticated actor, shared between self-service (SecurityController)
 * and admin actions (AdminUsersController) — both need the same check: a
 * password user re-enters their current password with the request. A
 * passkey-only user instead gets a fresh assertion done transparently at
 * the moment they submit the guarded form itself (webauthn.js's
 * data-step-up-passkey handling, driven by formAttr() below POSTing to
 * SecurityController's /account/stepup/passkey/* endpoints first, then
 * resubmitting the original form) — not a separate "verify first, then
 * come back and retry" step shown ahead of time. Either way the cookie
 * this class consumes is single-use, set the moment before the guarded
 * request actually lands.
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
     * Attribute to splice into the guarded <form ...> opening tag. A
     * passkey-only actor's step-up now happens transparently at submit
     * time (webauthn.js intercepts the submit, runs the ceremony against
     * this class's cookie, then resubmits the same form) rather than via a
     * separate visible "verify" control shown before every action —
     * empty for a password actor, who instead gets an inline password
     * field from fieldHtml() below.
     */
    public function formAttr(AuthUser $actor): string
    {
        return $actor->hasPassword() ? '' : ' data-step-up-passkey';
    }

    /**
     * Inline step-up UI for the form body. A password actor re-enters
     * their password directly; a passkey-only actor needs no visible
     * field (formAttr() above does the work) beyond an initially-empty
     * error slot for webauthn.js to report a failed/cancelled ceremony
     * into, scoped to this exact form via a plain querySelector('.step-up-error').
     */
    public function fieldHtml(AuthUser $actor): string
    {
        if (!$actor->hasPassword()) {
            return '<span class="step-up-error error"></span>';
        }

        return '<p class="step-up-field"><label>Current password'
            . '<input type="password" name="current_password" required></label></p>';
    }
}
