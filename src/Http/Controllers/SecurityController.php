<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Auth\AuditLog;
use App\Auth\AuthException;
use App\Auth\AuthUser;
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

        $body = '<h1>Set up an authenticator app</h1>'
            . '<p class="secret">' . View::e($totpData['secret']) . '</p>'
            . '<p><a href="' . View::e($totpData['provisioningUri']) . '">' . View::e($totpData['provisioningUri']) . '</a></p>'
            . $this->confirmTotpForm($user);

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
            View::render(
                'Set up authenticator',
                '<h1>Set up an authenticator app</h1><p class="error">Please re-verify to continue.</p>' . $this->confirmTotpForm($user),
                $user,
                $this->auth->csrfToken()
            );

            return;
        }

        $secret = (string) $pending['secret'];
        $code   = (string) ($_POST['code'] ?? '');

        if (!$this->totp->verifyPlaintext($secret, $code)) {
            $body = '<h1>Set up an authenticator app</h1><p class="error">Invalid code.</p>' . $this->confirmTotpForm($user);
            View::render('Set up authenticator', $body, $user, $this->auth->csrfToken());

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

            $body = '<h1>Authenticator app enabled</h1><p>Save your recovery codes — shown once:</p>'
                . '<ul>' . implode('', array_map(static fn (string $c): string => '<li class="secret">' . View::e($c) . '</li>', $plainCodes)) . '</ul>'
                . '<p><a href="/account/security">Back to security settings</a></p>';
            View::render('Recovery codes', $body, $user, $this->auth->csrfToken());

            return;
        }

        $this->audit->record($user->id, 'totp.enrolled', (string) $user->id, [], $this->clientIp());
        $this->renderPage($user, flash: 'Authenticator app enabled.');
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

        $body = '<h1>New recovery codes</h1><p>Your old codes no longer work. Save these — shown once:</p>'
            . '<ul>' . implode('', array_map(static fn (string $c): string => '<li class="secret">' . View::e($c) . '</li>', $plainCodes)) . '</ul>'
            . '<p><a href="/account/security">Back to security settings</a></p>';
        View::render('Recovery codes', $body, $user, $this->auth->csrfToken());
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

        $totpSection = $user->hasTotp()
            ? '<form method="post" action="/account/totp/remove" class="stack">'
                . View::csrfField($csrf) . $stepUpField
                . '<p><button type="submit">Remove password sign-in</button></p></form>'
            : '<p><a href="/account/totp/enroll">Set up an authenticator app</a></p>';

        $recoverySection = $user->hasTotp()
            ? '<form method="post" action="/account/recovery-codes/regenerate" class="stack">'
                . View::csrfField($csrf) . $stepUpField
                . '<p><button type="submit">Regenerate recovery codes</button></p></form>'
            : '';

        $passkeyRows = implode('', array_map(function (array $c) use ($csrf, $stepUpField): string {
            return '<tr><td>' . View::e($c['label'] ?? 'Passkey') . '</td>'
                . '<td>' . View::e($c['created_at']) . '</td>'
                . '<td><form method="post" action="/account/passkeys/remove" class="inline">'
                . View::csrfField($csrf) . $stepUpField
                . '<input type="hidden" name="credential_id" value="' . (int) $c['id'] . '">'
                . '<button type="submit">Remove</button></form></td></tr>';
        }, $this->webauthnStore->listForDisplay($user->id)));

        $body = '<h1>Security settings</h1>';

        if ($flash !== null) {
            $body .= '<p class="flash">' . View::e($flash) . '</p>';
        }

        if ($error !== null) {
            $body .= '<p class="error">' . View::e($error) . '</p>';
        }

        $body .= '<h2>Password</h2>';

        if ($user->hasPassword()) {
            $body .= '<form method="post" action="/account/password" class="stack">'
                . View::csrfField($csrf)
                . '<p><label for="current_password">Current password</label>'
                . '<input type="password" id="current_password" name="current_password" required></p>'
                . '<p><label for="new_password">New password</label>'
                . '<input type="password" id="new_password" name="new_password" minlength="' . PasswordHasher::MIN_LENGTH . '" required></p>'
                . '<p><label for="new_password_confirm">Confirm new password</label>'
                . '<input type="password" id="new_password_confirm" name="new_password_confirm" required></p>'
                . '<p><button type="submit">Change password</button></p>'
                . '</form>';
        } else {
            $body .= '<p>You sign in with a passkey only.</p>';
        }

        $body .= '<h2>Authenticator app</h2>' . $totpSection
            . ($recoverySection !== '' ? '<h2>Recovery codes</h2>' . $recoverySection : '')
            . '<h2>Passkeys</h2>'
            . ($passkeyRows !== '' ? '<table><tr><th>Label</th><th>Added</th><th></th></tr>' . $passkeyRows . '</table>' : '<p>None registered.</p>')
            . '<form class="stack" onsubmit="return false">'
            . View::csrfField($csrf)
            . $stepUpField
            . '<p><label for="passkey_label">Passkey name (optional)</label>'
            . '<input type="text" id="passkey_label" name="passkey_label" placeholder="e.g. Laptop"></p>'
            . '<p><button type="button" data-webauthn="register"'
            . ' data-options-url="/account/passkeys/register/options" data-verify-url="/account/passkeys/register/verify">Add a passkey</button></p>'
            . '</form>';

        if (!$user->hasPassword()) {
            $body .= '<h2>Re-verify (step-up)</h2>'
                . '<p>Passkey-only accounts must re-verify with a passkey before a sensitive change — click below, then retry the action.</p>'
                . '<form onsubmit="return false">' . View::csrfField($csrf)
                . '<p><button type="button" data-webauthn="authenticate"'
                . ' data-options-url="/account/stepup/passkey/options" data-verify-url="/account/stepup/passkey/verify">Verify with passkey</button></p>'
                . '</form>';
        }

        $body .= '<p id="webauthn-error" class="error"></p><script src="/assets/webauthn.js"></script>';

        View::render('Security settings', $body, $user, $csrf, $flash);
    }


    private function confirmTotpForm(AuthUser $user): string
    {
        $csrf = $this->auth->csrfToken();

        return '<form method="post" action="/account/totp/confirm" class="stack">'
            . View::csrfField($csrf)
            . $this->stepUp->fieldHtml($user)
            . '<p><label for="code">6-digit code</label>'
            . '<input type="text" id="code" name="code" required autofocus autocomplete="one-time-code"></p>'
            . '<p><button type="submit">Confirm</button></p>'
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
