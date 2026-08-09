<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Auth\AuditLog;
use App\Auth\AuthException;
use App\Auth\HibpBreachedPasswordChecker;
use App\Auth\InvitationService;
use App\Auth\PasswordHasher;
use App\Auth\RecoveryCodes;
use App\Auth\SealedCookie;
use App\Auth\SessionManager;
use App\Auth\TotpService;
use App\Auth\UserRepository;
use App\Auth\WebauthnCredentialStore;
use App\Auth\WebauthnService;
use App\Http\View;
use PDO;

/**
 * Invitation acceptance (spec §15.2): the invitee sets up their first
 * credential and — for the password path — mandatory MFA, all in one
 * flow. Nothing is written to `users`/`invitations` until the chosen
 * credential is fully verified: the password step stages a credential hash
 * and a not-yet-confirmed TOTP secret in a SealedCookie, and only the final
 * TOTP-confirm (or, on the passkey path, a successful registration
 * ceremony) commits everything — and consumes the invitation token — in one
 * go. A failure partway through never leaves a half-set-up account behind.
 */
final class InviteController
{
    private const string CEREMONY_COOKIE    = 'dmarc_ceremony';
    private const string PURPOSE_TOTP_SETUP = 'invite_totp_setup';
    private const string PURPOSE_PASSKEY    = 'invite_passkey';
    private const string ISSUER             = 'DMARC Analyzer';

    public function __construct(
        private readonly PDO $pdo,
        private readonly UserRepository $users,
        private readonly InvitationService $invitations,
        private readonly PasswordHasher $hasher,
        private readonly TotpService $totp,
        private readonly RecoveryCodes $recoveryCodes,
        private readonly int $recoveryCodesCount,
        private readonly SessionManager $sessions,
        private readonly WebauthnService $webauthn,
        private readonly WebauthnCredentialStore $webauthnStore,
        private readonly SealedCookie $sealed,
        private readonly AuditLog $audit,
        private readonly HibpBreachedPasswordChecker $breachChecker,
    ) {
    }

    public function showAccept(): void
    {
        $token = (string) ($_GET['token'] ?? '');

        try {
            $invite = $this->invitations->peek($token);
        } catch (AuthException $e) {
            View::render('Invitation', '<h1>Invitation</h1><p class="error">' . View::e($e->getMessage()) . '</p>', null);

            return;
        }

        $this->renderAcceptForm($token, $invite['email']);
    }

    public function startPassword(): void
    {
        $token = (string) ($_POST['token'] ?? '');

        try {
            $invite = $this->invitations->peek($token);
        } catch (AuthException $e) {
            View::render('Invitation', '<h1>Invitation</h1><p class="error">' . View::e($e->getMessage()) . '</p>', null);

            return;
        }

        $password = (string) ($_POST['password'] ?? '');
        $confirm  = (string) ($_POST['password_confirm'] ?? '');

        if ($password !== $confirm) {
            $this->renderAcceptForm($token, $invite['email'], 'Passwords do not match.');

            return;
        }

        if (!$this->hasher->meetsLengthPolicy($password)) {
            $this->renderAcceptForm(
                $token,
                $invite['email'],
                sprintf('Password must be %d–%d characters.', PasswordHasher::MIN_LENGTH, PasswordHasher::MAX_LENGTH)
            );

            return;
        }

        if ($this->breachChecker->isBreached($password)) {
            $this->renderAcceptForm($token, $invite['email'], 'This password has appeared in a known data breach. Choose a different password.');

            return;
        }

        $totpData = $this->totp->generate($invite['email'], self::ISSUER);

        $this->sealed->setCookie(self::CEREMONY_COOKIE, self::PURPOSE_TOTP_SETUP, [
            'token'           => $token,
            'email'           => $invite['email'],
            'credential_hash' => $this->hasher->hash($password),
            'secret'          => $totpData['secret'],
        ]);

        header('Location: /invite/totp-setup');
    }

    public function showTotpSetup(): void
    {
        $pending = $this->sealed->readCookie(self::CEREMONY_COOKIE, self::PURPOSE_TOTP_SETUP);

        if ($pending === null) {
            header('Location: /invite');

            return;
        }

        $this->renderTotpSetupForm((string) $pending['secret'], (string) $pending['email']);
    }

    public function confirmTotp(): void
    {
        $pending = $this->sealed->readCookie(self::CEREMONY_COOKIE, self::PURPOSE_TOTP_SETUP);

        if ($pending === null) {
            header('Location: /invite');

            return;
        }

        $secret = (string) $pending['secret'];
        $code   = (string) ($_POST['code'] ?? '');

        if (!$this->totp->verifyPlaintext($secret, $code)) {
            $this->renderTotpSetupForm($secret, (string) $pending['email'], 'Invalid code — try again.');

            return;
        }

        $this->sealed->clearCookie(self::CEREMONY_COOKIE);

        try {
            $invite = $this->invitations->accept((string) $pending['token']);
        } catch (AuthException $e) {
            View::render('Invitation', '<h1>Invitation</h1><p class="error">' . View::e($e->getMessage()) . '</p>', null);

            return;
        }

        $userId = $invite['userId'];
        $this->users->updateCredentialHash($userId, (string) $pending['credential_hash']);
        $this->users->updateTotpSecret($userId, $this->totp->encrypt($secret));
        $this->users->activate($userId);

        $plainCodes = $this->recoveryCodes->generateSet($this->recoveryCodesCount);
        $insert     = $this->pdo->prepare('INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)');

        foreach ($plainCodes as $plainCode) {
            $insert->execute([$userId, $this->recoveryCodes->hash($plainCode)]);
        }

        $this->users->touchLastLogin($userId);
        $this->sessions->create($userId, $this->clientIp(), $this->userAgent());
        $this->audit->record($userId, 'invitation.accepted', (string) $userId, ['method' => 'password_totp'], $this->clientIp());

        $this->renderRecoveryCodes($plainCodes);
    }

    /** POST /invite/accept-passkey/options — body: token. */
    public function passkeyOptions(): void
    {
        $token = (string) ($_POST['token'] ?? '');

        try {
            $invite = $this->invitations->peek($token);
        } catch (AuthException $e) {
            http_response_code(400);
            $this->json(['ok' => false, 'error' => $e->getMessage()]);

            return;
        }

        $options = $this->webauthn->creationOptions($invite['userId'], $invite['email'], []);
        $json    = $this->webauthn->serializeOptions($options);

        $this->sealed->setCookie(self::CEREMONY_COOKIE, self::PURPOSE_PASSKEY, [
            'token'   => $token,
            'options' => $json,
        ]);

        header('Content-Type: application/json');
        echo $json;
    }

    /** POST /invite/accept-passkey/verify — body: token, credential (JSON), label. */
    public function passkeyVerify(): void
    {
        $pending = $this->sealed->readCookie(self::CEREMONY_COOKIE, self::PURPOSE_PASSKEY);
        $this->sealed->clearCookie(self::CEREMONY_COOKIE);
        $token = (string) ($_POST['token'] ?? '');

        if ($pending === null || !hash_equals((string) $pending['token'], $token)) {
            http_response_code(400);
            $this->json(['ok' => false, 'error' => 'Passkey ceremony expired — try again.']);

            return;
        }

        try {
            $options    = $this->webauthn->deserializeCreationOptions((string) $pending['options']);
            $credential = $this->webauthn->decodeCredential((string) ($_POST['credential'] ?? ''));
            $record     = $this->webauthn->verifyRegistration($credential, $options);
            $invite     = $this->invitations->accept($token);
        } catch (AuthException $e) {
            http_response_code(400);
            $this->json(['ok' => false, 'error' => $e->getMessage()]);

            return;
        }

        $userId = $invite['userId'];
        $label  = trim((string) ($_POST['label'] ?? '')) ?: 'Passkey';

        $this->webauthnStore->save($userId, $record, $label);
        $this->users->activate($userId);
        $this->users->touchLastLogin($userId);
        $this->sessions->create($userId, $this->clientIp(), $this->userAgent());
        $this->audit->record($userId, 'invitation.accepted', (string) $userId, ['method' => 'passkey'], $this->clientIp());

        $this->json(['ok' => true, 'redirect' => '/']);
    }

    private function renderAcceptForm(string $token, string $email, ?string $error = null): void
    {
        $tokenField = '<input type="hidden" name="token" value="' . View::e($token) . '">';
        $body       = '<div class="narrow">'
            . '<div class="login-mark">' . View::icon('shield') . '</div>'
            . '<div class="card">'
            . '<h2 style="text-align:center;">Accept invitation</h2>'
            . '<p class="card-sub" style="text-align:center;">' . View::e($email) . '</p>';

        if ($error !== null) {
            $body .= '<p class="error">' . View::e($error) . '</p>';
        }

        $body .= '<form method="post" action="/invite/accept-password">'
            . $tokenField
            . '<div class="field"><label for="password">Password</label>'
            . '<input type="password" id="password" name="password" minlength="' . PasswordHasher::MIN_LENGTH . '" required autofocus autocomplete="new-password"></div>'
            . '<div class="field"><label for="password_confirm">Confirm password</label>'
            . '<input type="password" id="password_confirm" name="password_confirm" required autocomplete="new-password"></div>'
            . '<button type="submit" class="btn btn-primary btn-block" style="margin-top:6px;">Continue — you\'ll set up an authenticator app next</button>'
            . '</form>'
            . '</div>'

            . '<div class="card">'
            . '<h2>Or use a passkey instead</h2>'
            . '<p class="card-sub">A passkey signs you in without a password.</p>'
            . '<form onsubmit="return false">'
            . $tokenField
            . '<div class="field"><label for="passkey_label">Passkey name (optional)</label>'
            . '<input type="text" id="passkey_label" name="passkey_label" placeholder="e.g. Laptop"></div>'
            . '<button type="button" class="btn btn-secondary btn-block" data-webauthn="register"'
            . ' data-options-url="/invite/accept-passkey/options" data-verify-url="/invite/accept-passkey/verify"'
            . ' data-extra-fields="token">' . View::icon('key') . 'Register a passkey</button>'
            . '</form>'
            . '<p id="webauthn-error" class="error"></p>'
            . '</div>'
            . '</div>'
            . '<script src="/assets/webauthn.js"></script>';

        View::render('Accept invitation', $body, null);
    }

    private function renderTotpSetupForm(string $secret, string $email, ?string $error = null): void
    {
        $uri  = $this->totp->provisioningUriFor($secret, $email, self::ISSUER);
        $body = '<div class="narrow"><div class="card">'
            . '<h2>Set up your authenticator app</h2>'
            . '<p class="card-sub">Scan or enter this manually in an authenticator app (e.g. Google Authenticator, 1Password).</p>'
            . '<p class="secret" style="display:block; text-align:center; padding:10px; margin-bottom:12px;">' . View::e($secret) . '</p>';

        if ($error !== null) {
            $body .= '<p class="error">' . View::e($error) . '</p>';
        }

        $body .= '<form method="post" action="/invite/totp-confirm">'
            . '<div class="field"><label for="code">6-digit code</label>'
            . '<input type="text" id="code" name="code" required autofocus autocomplete="one-time-code"></div>'
            . '<button type="submit" class="btn btn-primary btn-block">Confirm</button>'
            . '</form></div></div>';

        View::render('Set up authenticator', $body, null);
    }

    /** @param list<string> $codes */
    private function renderRecoveryCodes(array $codes): void
    {
        $items = implode('', array_map(static fn (string $c): string => '<li class="secret">' . View::e($c) . '</li>', $codes));
        $body  = '<div class="narrow"><div class="card">'
            . '<h2>Save your recovery codes</h2>'
            . '<p class="card-sub">Each code can be used once if you lose access to your authenticator app. Store them somewhere safe — they will not be shown again.</p>'
            . '<ul class="secret-list">' . $items . '</ul>'
            . '<a href="/" class="btn btn-primary btn-block">Continue to the dashboard</a>'
            . '</div></div>';

        View::render('Recovery codes', $body, null);
    }

    private function json(mixed $data): void
    {
        header('Content-Type: application/json');
        echo json_encode($data, JSON_THROW_ON_ERROR);
    }

    private function clientIp(): ?string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? null;

        return \is_string($ip) && $ip !== '' ? $ip : null;
    }

    private function userAgent(): ?string
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;

        return \is_string($ua) ? $ua : null;
    }
}
