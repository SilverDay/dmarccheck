<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Auth\AuditLog;
use App\Auth\AuthException;
use App\Auth\AuthUser;
use App\Auth\HibpBreachedPasswordChecker;
use App\Auth\PasswordHasher;
use App\Auth\RecoveryCodes;
use App\Auth\SealedCookie;
use App\Auth\SessionManager;
use App\Auth\StepUp;
use App\Auth\TotpService;
use App\Auth\UserRepository;
use App\Auth\WebauthnCredentialStore;
use App\Auth\WebauthnService;
use App\Auth\WebauthnUserHandle;
use App\Http\AuthMiddleware;
use App\Http\View;
use PDO;

/**
 * Self-service credential management (spec §15.4). Every mutating action
 * here is step-up guarded: a password user re-enters their current
 * password in the same request; a passkey-only user instead does a fresh
 * passkey assertion first (POST /account/stepup/passkey/*), which stamps a
 * short-lived, single-use "verified" SealedCookie that the next action
 * consumes. Removing the last remaining factor is always blocked — MFA is
 * mandatory (§15.3).
 */
final class SecurityController
{
    private const string CEREMONY_COOKIE          = 'dmarc_ceremony';
    private const string PURPOSE_STEPUP_CHALLENGE = 'stepup_challenge';
    private const string PURPOSE_TOTP_ENROLL      = 'totp_enroll';
    private const string ISSUER                   = 'DMARC Analyzer';

    public function __construct(
        private readonly PDO $pdo,
        private readonly UserRepository $users,
        private readonly PasswordHasher $hasher,
        private readonly TotpService $totp,
        private readonly RecoveryCodes $recoveryCodes,
        private readonly int $recoveryCodesCount,
        private readonly SessionManager $sessions,
        private readonly WebauthnService $webauthn,
        private readonly WebauthnCredentialStore $webauthnStore,
        private readonly SealedCookie $sealed,
        private readonly StepUp $stepUp,
        private readonly AuditLog $audit,
        private readonly AuthMiddleware $auth,
        private readonly HibpBreachedPasswordChecker $breachChecker,
    ) {
    }

    public function show(AuthUser $user): void
    {
        $this->renderPage($user);
    }

    public function changePassword(AuthUser $user): void
    {
        if (!$this->stepUp->verify($user)) {
            $this->renderPage($user, error: 'Please re-enter your current password (or verify with a passkey) to continue.');

            return;
        }

        $password = (string) ($_POST['new_password'] ?? '');
        $confirm  = (string) ($_POST['new_password_confirm'] ?? '');

        if ($password !== $confirm || !$this->hasher->meetsLengthPolicy($password)) {
            $this->renderPage($user, error: sprintf(
                'New password must match and be %d–%d characters.',
                PasswordHasher::MIN_LENGTH,
                PasswordHasher::MAX_LENGTH
            ));

            return;
        }

        if ($this->breachChecker->isBreached($password)) {
            $this->renderPage($user, error: 'This password has appeared in a known data breach. Choose a different password.');

            return;
        }

        $this->users->updateCredentialHash($user->id, $this->hasher->hash($password));
        $session = $this->sessionToken();

        if ($session !== null) {
            $this->sessions->destroyOthersForUser($user->id, $session);
        }

        $this->audit->record($user->id, 'password.changed', (string) $user->id, [], $this->clientIp());
        $this->renderPage($user, flash: 'Password changed. Other sessions were signed out.');
    }

    public function showTotpEnroll(AuthUser $user): void
    {
        $totpData = $this->totp->generate($user->email, self::ISSUER);
        $this->sealed->setCookie(self::CEREMONY_COOKIE, self::PURPOSE_TOTP_ENROLL, ['secret' => $totpData['secret']]);

        $body = '<div class="narrow"><div class="card">'
            . '<h2>Set up an authenticator app</h2>'
            . '<p class="card-sub">Scan or enter this manually in an authenticator app (e.g. Google Authenticator, 1Password).</p>'
            . '<p class="secret secret-block">' . View::e($totpData['secret']) . '</p>'
            . $this->confirmTotpForm($user)
            . '</div></div>';

        View::render('Set up authenticator', $body, $user, $this->auth->csrfToken());
    }

    public function confirmTotpEnroll(AuthUser $user): void
    {
        $pending = $this->sealed->readCookie(self::CEREMONY_COOKIE, self::PURPOSE_TOTP_ENROLL);

        if ($pending === null) {
            header('Location: /account/totp/enroll');

            return;
        }

        if (!$this->stepUp->verify($user)) {
            $this->renderTotpConfirmError($user, 'Please re-verify to continue.');

            return;
        }

        $secret = (string) $pending['secret'];
        $code   = (string) ($_POST['code'] ?? '');

        if (!$this->totp->verifyPlaintext($secret, $code)) {
            $this->renderTotpConfirmError($user, 'Invalid code.');

            return;
        }

        $this->sealed->clearCookie(self::CEREMONY_COOKIE);
        $this->users->updateTotpSecret($user->id, $this->totp->encrypt($secret));

        $countStmt = $this->pdo->prepare('SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?');
        $countStmt->execute([$user->id]);

        if ((int) $countStmt->fetchColumn() === 0) {
            $plainCodes = $this->recoveryCodes->generateSet($this->recoveryCodesCount);
            $insert     = $this->pdo->prepare('INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)');

            foreach ($plainCodes as $plainCode) {
                $insert->execute([$user->id, $this->recoveryCodes->hash($plainCode)]);
            }

            $this->audit->record($user->id, 'totp.enrolled', (string) $user->id, [], $this->clientIp());
            $this->renderRecoveryCodesPage($user, 'Authenticator app enabled', $plainCodes);

            return;
        }

        $this->audit->record($user->id, 'totp.enrolled', (string) $user->id, [], $this->clientIp());
        $this->renderPage($user, flash: 'Authenticator app enabled.');
    }

    private function renderTotpConfirmError(AuthUser $user, string $error): void
    {
        $body = '<div class="narrow"><div class="card">'
            . '<h2>Set up an authenticator app</h2>'
            . '<p class="error">' . View::e($error) . '</p>'
            . $this->confirmTotpForm($user)
            . '</div></div>';
        View::render('Set up authenticator', $body, $user, $this->auth->csrfToken());
    }

    /** @param list<string> $codes */
    private function renderRecoveryCodesPage(AuthUser $user, string $title, array $codes, ?string $subtitle = null): void
    {
        $items = implode('', array_map(static fn (string $c): string => '<li class="secret">' . View::e($c) . '</li>', $codes));
        $body  = '<div class="narrow"><div class="card">'
            . '<h2>' . View::e($title) . '</h2>'
            . '<p class="card-sub">' . View::e($subtitle ?? 'Save your recovery codes — shown once.') . '</p>'
            . '<ul class="secret-list">' . $items . '</ul>'
            . '<a href="/account/security" class="btn btn-primary btn-block">Back to security settings</a>'
            . '</div></div>';
        View::render('Recovery codes', $body, $user, $this->auth->csrfToken());
    }

    public function removeTotp(AuthUser $user): void
    {
        if ($this->webauthnStore->countForUser($user->id) === 0) {
            $this->renderPage($user, error: 'Cannot remove your authenticator app — it is your only sign-in method. Add a passkey first.');

            return;
        }

        if (!$this->stepUp->verify($user)) {
            $this->renderPage($user, error: 'Please re-verify to continue.');

            return;
        }

        $this->pdo->prepare('DELETE FROM recovery_codes WHERE user_id = ?')->execute([$user->id]);
        $stmt = $this->pdo->prepare('UPDATE users SET credential_hash = NULL, totp_secret = NULL WHERE id = ?');
        $stmt->execute([$user->id]);

        $this->audit->record($user->id, 'totp.removed', (string) $user->id, [], $this->clientIp());
        $this->renderPage($user, flash: 'Password sign-in removed. You now sign in with a passkey only.');
    }

    public function regenerateRecoveryCodes(AuthUser $user): void
    {
        if (!$user->hasTotp()) {
            $this->renderPage($user, error: 'Recovery codes require an authenticator app.');

            return;
        }

        if (!$this->stepUp->verify($user)) {
            $this->renderPage($user, error: 'Please re-verify to continue.');

            return;
        }

        $this->pdo->prepare('DELETE FROM recovery_codes WHERE user_id = ?')->execute([$user->id]);
        $plainCodes = $this->recoveryCodes->generateSet($this->recoveryCodesCount);
        $insert     = $this->pdo->prepare('INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)');

        foreach ($plainCodes as $plainCode) {
            $insert->execute([$user->id, $this->recoveryCodes->hash($plainCode)]);
        }

        $this->audit->record($user->id, 'recovery_codes.regenerated', (string) $user->id, [], $this->clientIp());
        $this->renderRecoveryCodesPage($user, 'New recovery codes', $plainCodes, 'Your old codes no longer work. Save these — shown once.');
    }

    /** POST /account/passkeys/register/options */
    public function passkeyRegisterOptions(AuthUser $user): void
    {
        if (!$this->stepUp->verify($user)) {
            http_response_code(400);
            $this->json(['ok' => false, 'error' => 'Please re-verify to continue.']);

            return;
        }

        $existing = array_map(
            static fn ($c) => $c->publicKeyCredentialId,
            $this->webauthnStore->findAllForUser($user->id)
        );
        $options = $this->webauthn->creationOptions($user->id, $user->email, $existing);
        $json    = $this->webauthn->serializeOptions($options);

        $this->sealed->setCookie(self::CEREMONY_COOKIE, 'passkey_register', ['options' => $json]);

        header('Content-Type: application/json');
        echo $json;
    }

    /** POST /account/passkeys/register/verify */
    public function passkeyRegisterVerify(AuthUser $user): void
    {
        $pending = $this->sealed->readCookie(self::CEREMONY_COOKIE, 'passkey_register');
        $this->sealed->clearCookie(self::CEREMONY_COOKIE);

        if ($pending === null) {
            http_response_code(400);
            $this->json(['ok' => false, 'error' => 'Passkey ceremony expired — try again.']);

            return;
        }

        try {
            $options    = $this->webauthn->deserializeCreationOptions((string) $pending['options']);
            $credential = $this->webauthn->decodeCredential((string) ($_POST['credential'] ?? ''));
            $record     = $this->webauthn->verifyRegistration($credential, $options);
        } catch (\Throwable $e) {
            http_response_code(400);
            $this->json(['ok' => false, 'error' => $e instanceof AuthException ? $e->getMessage() : 'Passkey registration failed.']);

            return;
        }

        $label = trim((string) ($_POST['label'] ?? '')) ?: 'Passkey';
        $this->webauthnStore->save($user->id, $record, $label);
        $this->audit->record($user->id, 'passkey.enrolled', (string) $user->id, ['label' => $label], $this->clientIp());

        $this->json(['ok' => true, 'redirect' => '/account/security']);
    }

    public function removePasskey(AuthUser $user): void
    {
        $credentialRowId  = (int) ($_POST['credential_id'] ?? 0);
        $remainingFactors = $this->webauthnStore->countForUser($user->id) - 1 + ($user->hasTotp() ? 1 : 0);

        if ($remainingFactors < 1) {
            $this->renderPage($user, error: 'Cannot remove your last sign-in method.');

            return;
        }

        if (!$this->stepUp->verify($user)) {
            $this->renderPage($user, error: 'Please re-verify to continue.');

            return;
        }

        $this->webauthnStore->remove($user->id, $credentialRowId);
        $this->audit->record($user->id, 'passkey.removed', (string) $credentialRowId, [], $this->clientIp());
        $this->renderPage($user, flash: 'Passkey removed.');
    }

    /** POST /account/stepup/passkey/options — passkey-only users re-verifying for a sensitive action. */
    public function stepUpOptions(AuthUser $user): void
    {
        $ids = array_map(
            static fn ($c) => $c->publicKeyCredentialId,
            $this->webauthnStore->findAllForUser($user->id)
        );

        if ($ids === []) {
            http_response_code(400);
            $this->json(['ok' => false, 'error' => 'No passkeys registered.']);

            return;
        }

        $options = $this->webauthn->requestOptions($ids);
        $json    = $this->webauthn->serializeOptions($options);
        $this->sealed->setCookie(self::CEREMONY_COOKIE, self::PURPOSE_STEPUP_CHALLENGE, ['options' => $json]);

        header('Content-Type: application/json');
        echo $json;
    }

    public function stepUpVerify(AuthUser $user): void
    {
        $pending = $this->sealed->readCookie(self::CEREMONY_COOKIE, self::PURPOSE_STEPUP_CHALLENGE);
        $this->sealed->clearCookie(self::CEREMONY_COOKIE);

        if ($pending === null) {
            http_response_code(400);
            $this->json(['ok' => false, 'error' => 'Verification expired — try again.']);

            return;
        }

        try {
            $options    = $this->webauthn->deserializeRequestOptions((string) $pending['options']);
            $credential = $this->webauthn->decodeCredential((string) ($_POST['credential'] ?? ''));
            $stored     = $this->webauthnStore->findByCredentialId($credential->rawId);

            if ($stored === null) {
                throw new AuthException('Unknown passkey.');
            }

            $updated = $this->webauthn->verifyAuthentication($credential, $options, $stored, WebauthnUserHandle::forUser($user->id));
        } catch (\Throwable $e) {
            http_response_code(400);
            $this->json(['ok' => false, 'error' => $e instanceof AuthException ? $e->getMessage() : 'Verification failed.']);

            return;
        }

        $this->webauthnStore->updateSignCount($updated->publicKeyCredentialId, $updated->counter);
        $this->sealed->setCookie(self::CEREMONY_COOKIE, StepUp::PURPOSE_OK, ['user_id' => $user->id]);

        $this->json(['ok' => true, 'redirect' => '/account/security']);
    }


    private function renderPage(AuthUser $user, ?string $flash = null, ?string $error = null): void
    {
        $csrf        = $this->auth->csrfToken();
        $stepUpField = $this->stepUp->fieldHtml($user);

        $body = '<div class="page-head"><div><h1>Security settings</h1><div class="sub">' . View::e($user->email) . '</div></div></div>';

        if ($error !== null) {
            $body .= '<p class="error">' . View::e($error) . '</p>';
        }

        $body .= '<div class="narrow narrow-notop">';

        // --- Password ---
        $body .= '<div class="card"><h2>Password</h2>';

        if ($user->hasPassword()) {
            $body .= '<form method="post" action="/account/password">'
                . View::csrfField($csrf)
                . '<div class="field"><label for="current_password">Current password</label>'
                . '<input type="password" id="current_password" name="current_password" required autocomplete="current-password"></div>'
                . '<div class="field"><label for="new_password">New password</label>'
                . '<input type="password" id="new_password" name="new_password" minlength="' . PasswordHasher::MIN_LENGTH . '" required autocomplete="new-password"></div>'
                . '<div class="field"><label for="new_password_confirm">Confirm new password</label>'
                . '<input type="password" id="new_password_confirm" name="new_password_confirm" required autocomplete="new-password"></div>'
                . '<button type="submit" class="btn btn-secondary mt-sm">Update password</button>'
                . '</form>';
        } else {
            $body .= '<p class="card-sub">You sign in with a passkey only.</p>';
        }

        $body .= '</div>';

        // --- Authenticator app ---
        $body .= '<div class="card"><h2>Authenticator app</h2>';

        if ($user->hasTotp()) {
            $body .= '<p class="card-sub">' . View::badge('success', 'Enabled') . '</p>'
                . '<div class="list-row"><div class="meta">' . View::icon('key')
                . '<div><div class="name">Recovery codes</div><div class="detail">Regenerate if you\'re running low</div></div></div>'
                . '<form method="post" action="/account/recovery-codes/regenerate">' . View::csrfField($csrf) . $stepUpField
                . '<button type="submit" class="btn btn-secondary btn-sm">Regenerate</button></form></div>'
                . '<form method="post" action="/account/totp/remove" class="mt-md">'
                . View::csrfField($csrf) . $stepUpField
                . '<button type="submit" class="btn btn-danger">' . View::icon('trash') . 'Remove password sign-in</button></form>';
        } else {
            $body .= '<p class="card-sub">Not set up.</p>'
                . '<a href="/account/totp/enroll" class="btn btn-secondary">' . View::icon('lock') . 'Set up an authenticator app</a>';
        }

        $body .= '</div>';

        // --- Passkeys ---
        $passkeys = $this->webauthnStore->listForDisplay($user->id);
        $body .= '<div class="card"><h2>Passkeys</h2>'
            . '<p class="card-sub">' . \count($passkeys) . ' registered &mdash; a passkey signs you in without a password.</p>';

        foreach ($passkeys as $c) {
            $body .= '<div class="list-row"><div class="meta">' . View::icon('key')
                . '<div><div class="name">' . View::e((string) ($c['label'] ?? 'Passkey')) . '</div>'
                . '<div class="detail">Added ' . View::e($c['created_at']) . '</div></div></div>'
                . '<form method="post" action="/account/passkeys/remove">'
                . View::csrfField($csrf) . $stepUpField
                . '<input type="hidden" name="credential_id" value="' . (int) $c['id'] . '">'
                . '<button type="submit" class="btn btn-danger btn-sm">' . View::icon('trash') . 'Remove</button></form></div>';
        }

        $body .= '<form onsubmit="return false" class="mt-md">'
            . View::csrfField($csrf) . $stepUpField
            . '<div class="field"><label for="passkey_label">Passkey name (optional)</label>'
            . '<input type="text" id="passkey_label" name="passkey_label" placeholder="e.g. Laptop"></div>'
            . '<button type="button" class="btn btn-secondary" data-webauthn="register"'
            . ' data-options-url="/account/passkeys/register/options" data-verify-url="/account/passkeys/register/verify"'
            . ' data-error-target="#webauthn-error-register">'
            . View::icon('key') . 'Add a passkey</button>'
            . '<p id="webauthn-error-register" class="error"></p>'
            . '</form></div>';

        if (!$user->hasPassword()) {
            $body .= '<div class="card"><h2>Re-verify</h2>'
                . '<p class="card-sub">Passkey-only accounts re-verify with a passkey before a sensitive change — verify here, then retry the action below.</p>'
                . '<form onsubmit="return false">' . View::csrfField($csrf)
                . '<button type="button" class="btn btn-secondary" data-webauthn="authenticate"'
                . ' data-options-url="/account/stepup/passkey/options" data-verify-url="/account/stepup/passkey/verify"'
                . ' data-error-target="#webauthn-error-stepup">'
                . View::icon('key') . 'Verify with passkey</button>'
                . '<p id="webauthn-error-stepup" class="error"></p>'
                . '</form></div>';
        }

        $body .= '</div><script src="/assets/webauthn.js"></script>';

        View::render('Security settings', $body, $user, $csrf, $flash);
    }

    private function confirmTotpForm(AuthUser $user): string
    {
        $csrf = $this->auth->csrfToken();

        return '<form method="post" action="/account/totp/confirm">'
            . View::csrfField($csrf)
            . $this->stepUp->fieldHtml($user)
            . '<div class="field"><label for="code">6-digit code</label>'
            . '<input type="text" id="code" name="code" required autofocus autocomplete="one-time-code"></div>'
            . '<button type="submit" class="btn btn-primary btn-block">Confirm</button>'
            . '</form>';
    }

    private function json(mixed $data): void
    {
        header('Content-Type: application/json');
        echo json_encode($data, JSON_THROW_ON_ERROR);
    }

    private function sessionToken(): ?string
    {
        $session = $this->sessions->current();

        return $session?->token;
    }

    private function clientIp(): ?string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? null;

        return \is_string($ip) && $ip !== '' ? $ip : null;
    }
}
