<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Auth\AuditLog;
use App\Auth\AuthException;
use App\Auth\LoginRateLimiter;
use App\Auth\PasswordHasher;
use App\Auth\RecoveryCodes;
use App\Auth\SealedCookie;
use App\Auth\SessionManager;
use App\Auth\TotpService;
use App\Auth\UserRepository;
use App\Auth\WebauthnCredentialStore;
use App\Auth\WebauthnService;
use App\Auth\WebauthnUserHandle;
use App\Http\AuthMiddleware;
use App\Http\View;
use PDO;

/**
 * Login (spec §15.3): password step, TOTP/recovery-code second-factor
 * step, and one-step passkey login (a passkey satisfies MFA on its own).
 *
 * The password->TOTP handoff has no session yet, so it's carried in a
 * SealedCookie rather than $_SESSION — same mechanism the passkey login
 * ceremony uses to correlate its options/verify round trip.
 */
final class AuthController
{
    private const string CEREMONY_COOKIE = 'dmarc_ceremony';
    private const string PURPOSE_2FA     = 'login_2fa';
    private const string PURPOSE_PASSKEY = 'login_passkey';

    /**
     * Pre-computed Argon2id hash of the string "dummy" — used only to ensure
     * the login path always spends Argon2id time regardless of whether the
     * submitted email exists, preventing timing-based user enumeration (F-03).
     * Generated once with password_hash('dummy', PASSWORD_ARGON2ID).
     */
    private const string DUMMY_HASH = '$argon2id$v=19$m=65536,t=4,p=1$NVNaYnpJNDZlRGcxZUtQYQ$fFOFpvaepRsqncV9HdTrsEGf1eP3snd+vz3Toh/OMSU';

    public function __construct(
        private readonly PDO $pdo,
        private readonly UserRepository $users,
        private readonly PasswordHasher $hasher,
        private readonly TotpService $totp,
        private readonly RecoveryCodes $recoveryCodes,
        private readonly SessionManager $sessions,
        private readonly WebauthnService $webauthn,
        private readonly WebauthnCredentialStore $webauthnStore,
        private readonly SealedCookie $sealed,
        private readonly AuditLog $audit,
        private readonly AuthMiddleware $auth,
        private readonly LoginRateLimiter $rateLimiter,
    ) {
    }

    public function showLogin(): void
    {
        if ($this->auth->currentUser() !== null) {
            header('Location: /');

            return;
        }

        $this->renderLoginForm();
    }

    public function login(): void
    {
        $email    = trim((string) ($_POST['email'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');

        // Rate limit by IP before any DB lookup (F-04). The check is done
        // before findByEmail() so rate-limited responses still consume Argon2id
        // time (via DUMMY_HASH below) to avoid exposing a fast-path.
        $ip           = $this->clientIp();
        $rateLimited  = !$this->rateLimiter->check($ip);

        $user = $this->users->findByEmail($email);

        // Always run Argon2id verification regardless of whether the user exists,
        // so response timing does not reveal whether the email is registered (F-03).
        $hashToVerify = ($user !== null && $user->hasPassword())
            ? (string) $user->credentialHash
            : self::DUMMY_HASH;
        $passwordOk = $this->hasher->verify($password, $hashToVerify);

        if ($rateLimited) {
            $this->renderLoginForm('Too many login attempts. Please wait and try again.', $email);

            return;
        }

        if ($user === null || !$user->isActive() || !$user->hasPassword() || !$passwordOk) {
            $this->rateLimiter->recordFailure($ip);
            $this->audit->record(null, 'login.failed', $email, ['reason' => 'bad_credentials'], $this->clientIp());
            $this->renderLoginForm('Invalid email or password.', $email);

            return;
        }

        if (!$user->hasTotp()) {
            // Mandatory-MFA invariant violated (shouldn't happen for an active
            // password user — accept-invite always sets up TOTP together with
            // the password). Fail closed rather than allow a single-factor login.
            $this->audit->record($user->id, 'login.failed', $user->email, ['reason' => 'no_second_factor'], $this->clientIp());
            $this->renderLoginForm('Account setup is incomplete — contact an administrator.', $email);

            return;
        }

        $this->sealed->setCookie(self::CEREMONY_COOKIE, self::PURPOSE_2FA, ['user_id' => $user->id]);
        header('Location: /login/totp');
    }

    public function showTotp(): void
    {
        if ($this->sealed->readCookie(self::CEREMONY_COOKIE, self::PURPOSE_2FA) === null) {
            header('Location: /login');

            return;
        }

        $this->renderTotpForm();
    }

    public function verifyTotp(): void
    {
        $pending = $this->sealed->readCookie(self::CEREMONY_COOKIE, self::PURPOSE_2FA);

        if ($pending === null) {
            header('Location: /login');

            return;
        }

        $user = $this->users->findById((int) $pending['user_id']);

        if ($user === null || !$user->isActive()) {
            $this->sealed->clearCookie(self::CEREMONY_COOKIE);
            header('Location: /login');

            return;
        }

        $code   = trim((string) ($_POST['code'] ?? ''));
        $method = str_contains($code, '-') ? 'recovery_code' : 'totp';

        // Rate limit the TOTP step too — TOTP has only 10⁶ codes and
        // recovery codes are finite (F-04).
        $ip = $this->clientIp();

        if (!$this->rateLimiter->check($ip)) {
            $this->renderTotpForm('Too many login attempts. Please wait and try again.');

            return;
        }

        $ok     = $method === 'totp'
            ? $this->verifyTotpWithReplayProtection($user->id, (string) $user->totpSecretEncrypted, $code)
            : $this->consumeRecoveryCode($user->id, $code);

        if (!$ok) {
            $this->rateLimiter->recordFailure($ip);
            $this->audit->record($user->id, 'login.failed', $user->email, ['reason' => 'bad_' . $method], $this->clientIp());
            $this->renderTotpForm('Invalid code.');

            return;
        }

        $this->sealed->clearCookie(self::CEREMONY_COOKIE);
        $this->completeLogin($user->id, $method);
    }

    /** POST /login/passkey/options — body: email. Returns request options JSON. */
    public function passkeyOptions(): void
    {
        $email       = trim((string) ($_POST['email'] ?? ''));
        $user        = $this->users->findByEmail($email);
        $credentials = $user === null ? [] : $this->webauthnStore->findAllForUser($user->id);

        if ($user === null || !$user->isActive() || $credentials === []) {
            http_response_code(400);
            $this->json(['ok' => false, 'error' => 'No passkeys available for that account.']);

            return;
        }

        $ids     = array_map(static fn ($c) => $c->publicKeyCredentialId, $credentials);
        $options = $this->webauthn->requestOptions($ids);
        $json    = $this->webauthn->serializeOptions($options);

        $this->sealed->setCookie(self::CEREMONY_COOKIE, self::PURPOSE_PASSKEY, [
            'user_id' => $user->id,
            'options' => $json,
        ]);

        header('Content-Type: application/json');
        echo $json;
    }

    /** POST /login/passkey/verify — body: email, credential (JSON). */
    public function passkeyVerify(): void
    {
        $pending = $this->sealed->readCookie(self::CEREMONY_COOKIE, self::PURPOSE_PASSKEY);
        $this->sealed->clearCookie(self::CEREMONY_COOKIE);

        if ($pending === null) {
            http_response_code(400);
            $this->json(['ok' => false, 'error' => 'Passkey ceremony expired — try again.']);

            return;
        }

        $userId = (int) $pending['user_id'];
        $user   = $this->users->findById($userId);

        if ($user === null || !$user->isActive()) {
            http_response_code(400);
            $this->json(['ok' => false, 'error' => 'Account is not available.']);

            return;
        }

        try {
            $options    = $this->webauthn->deserializeRequestOptions((string) $pending['options']);
            $credential = $this->webauthn->decodeCredential((string) ($_POST['credential'] ?? ''));
            $stored     = $this->webauthnStore->findByCredentialId($credential->rawId);

            if ($stored === null) {
                throw new AuthException('Unknown passkey.');
            }

            $updated = $this->webauthn->verifyAuthentication(
                $credential,
                $options,
                $stored,
                WebauthnUserHandle::forUser($userId),
            );
        } catch (\Throwable $e) {
            $this->audit->record($userId, 'login.failed', $user->email, ['reason' => 'bad_passkey'], $this->clientIp());
            http_response_code(400);
            $this->json(['ok' => false, 'error' => $e instanceof AuthException ? $e->getMessage() : 'Passkey verification failed.']);

            return;
        }

        $this->webauthnStore->updateSignCount($updated->publicKeyCredentialId, $updated->counter);
        $this->completeLoginJson($user->id, 'passkey');
    }

    public function logout(): void
    {
        $this->sessions->destroy();
        header('Location: /login');
    }

    private function completeLogin(int $userId, string $method): void
    {
        $this->sessions->create($userId, $this->clientIp(), $this->userAgent());
        $this->users->touchLastLogin($userId);
        $this->audit->record($userId, 'login.success', (string) $userId, ['method' => $method], $this->clientIp());
        header('Location: /');
    }

    private function completeLoginJson(int $userId, string $method): void
    {
        $this->sessions->create($userId, $this->clientIp(), $this->userAgent());
        $this->users->touchLastLogin($userId);
        $this->audit->record($userId, 'login.success', (string) $userId, ['method' => $method], $this->clientIp());
        $this->json(['ok' => true, 'redirect' => '/']);
    }

    /**
     * Verify a TOTP code and reject it if the same period counter has already
     * been accepted for this user (replay protection — F-02, NIST SP 800-63B §5.1.3.2).
     * The unique constraint on used_totp_codes(user_id, period) provides a
     * DB-level backstop against concurrent replays.
     */
    private function verifyTotpWithReplayProtection(int $userId, string $encryptedSecret, string $code): bool
    {
        $period = $this->totp->verifyGetPeriod($encryptedSecret, $code);

        if ($period === null) {
            return false;
        }

        // Attempt to INSERT the period counter; a duplicate means this code was
        // already used and the INSERT will fail via the unique constraint.
        try {
            $this->pdo->prepare(
                'INSERT INTO used_totp_codes (user_id, period) VALUES (?, ?)'
            )->execute([$userId, $period]);
        } catch (\PDOException $e) {
            // Duplicate key — code already consumed in this period.
            if (str_starts_with($e->getCode(), '23')) {
                return false;
            }
            throw $e;
        }

        // Prune entries older than 2 minutes (leeway * 2 + buffer) so the
        // table stays small without needing a separate cron job.
        $this->pdo->prepare(
            'DELETE FROM used_totp_codes WHERE used_at < DATE_SUB(NOW(), INTERVAL 2 MINUTE)'
        )->execute();

        return true;
    }

    private function consumeRecoveryCode(int $userId, string $submitted): bool
    {
        // SELECT … FOR UPDATE acquires row-level locks before the PHP match,
        // preventing two concurrent requests from both seeing consumed_at = NULL
        // and consuming the same code (TOCTOU race — F-01).
        $this->pdo->beginTransaction();

        try {
            $stmt = $this->pdo->prepare(
                'SELECT id, code_hash, consumed_at FROM recovery_codes WHERE user_id = ? FOR UPDATE'
            );
            $stmt->execute([$userId]);
            /** @var list<array{id: int, code_hash: string, consumed_at: ?string}> $rows */
            $rows = $stmt->fetchAll();

            $matchId = $this->recoveryCodes->findMatch($rows, $submitted);

            if ($matchId === null) {
                $this->pdo->rollBack();

                return false;
            }

            $this->pdo->prepare('UPDATE recovery_codes SET consumed_at = NOW() WHERE id = ?')->execute([$matchId]);
            $this->pdo->commit();

            return true;
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    private function renderLoginForm(?string $error = null, string $email = ''): void
    {
        $body = '<div class="narrow" style="max-width:400px;">'
            . '<div class="login-mark">' . View::icon('shield') . '</div>'
            . '<div class="card">'
            . '<h2 style="text-align:center;">Sign in</h2>'
            . '<p class="card-sub" style="text-align:center;">DMARC Analyzer</p>';

        if ($error !== null) {
            $body .= '<p class="error">' . View::e($error) . '</p>';
        }

        $body .= '<form method="post" action="/login">'
            . '<div class="field"><label for="email">Email</label>'
            . '<input type="email" id="email" name="email" value="' . View::e($email) . '" required autofocus autocomplete="email"></div>'
            . '<div class="field"><label for="password">Password</label>'
            . '<input type="password" id="password" name="password" required autocomplete="current-password"></div>'
            . '<button type="submit" class="btn btn-primary btn-block" style="margin-top:6px;">Continue</button>'
            . '</form>'
            . '<div class="divider-label" style="margin-top:16px;">or</div>'
            . '<button type="button" class="btn btn-secondary btn-block" data-webauthn="authenticate"'
            . ' data-options-url="/login/passkey/options" data-verify-url="/login/passkey/verify"'
            . ' data-extra-fields="email">' . View::icon('key') . 'Sign in with a passkey</button>'
            . '<p id="webauthn-error" class="error"></p>'
            . '</div>'
            . '<div class="helper-link"><a href="/password-reset">Forgot your password?</a></div>'
            . '</div>'
            . '<script src="/assets/webauthn.js"></script>';

        View::render('Log in', $body, null);
    }

    private function renderTotpForm(?string $error = null): void
    {
        $body = '<div class="narrow" style="max-width:400px;"><div class="card">'
            . '<h2>Verification code</h2>'
            . '<p class="card-sub">Enter the 6-digit code from your authenticator app, or a recovery code.</p>';

        if ($error !== null) {
            $body .= '<p class="error">' . View::e($error) . '</p>';
        }

        $body .= '<form method="post" action="/login/totp">'
            . '<div class="field"><label for="code">Code</label>'
            . '<input type="text" id="code" name="code" required autofocus autocomplete="one-time-code"></div>'
            . '<button type="submit" class="btn btn-primary btn-block">Verify</button>'
            . '</form></div></div>';

        View::render('Verification code', $body, null);
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
