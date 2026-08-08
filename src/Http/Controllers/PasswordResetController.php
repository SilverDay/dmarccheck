<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Auth\AuditLog;
use App\Auth\AuthException;
use App\Auth\Mailer;
use App\Auth\PasswordHasher;
use App\Auth\PasswordResetService;
use App\Auth\SessionManager;
use App\Http\View;

/**
 * Self-service password reset (spec §15.4). The request step always shows
 * the same message regardless of whether the address exists — non
 * -enumerating by construction, since PasswordResetService::request()
 * itself returns null for both "no such account" and "rate limited".
 */
final class PasswordResetController
{
    public function __construct(
        private readonly PasswordResetService $resets,
        private readonly PasswordHasher $hasher,
        private readonly Mailer $mailer,
        private readonly SessionManager $sessions,
        private readonly AuditLog $audit,
        private readonly string $baseUrl,
    ) {
    }

    public function showRequest(): void
    {
        $this->renderRequestForm();
    }

    public function request(): void
    {
        $email = trim((string) ($_POST['email'] ?? ''));
        $token = $this->resets->request($email);

        if ($token !== null) {
            $link = rtrim($this->baseUrl, '/') . '/password-reset/confirm?token=' . urlencode($token);
            $this->mailer->send(
                $email,
                'Reset your DMARC Analyzer password',
                "Use this link to reset your password (expires shortly):\n\n{$link}\n\nIf you didn't request this, ignore this email."
            );
        }

        $body = '<div class="narrow"><div class="card">'
            . '<h2>Password reset</h2>'
            . '<p class="card-sub">If that address has an account, a reset link has been sent.</p>'
            . '<a href="/login" class="btn btn-secondary btn-block">Back to login</a>'
            . '</div></div>';
        View::render('Password reset', $body, null);
    }

    public function showConfirm(): void
    {
        $token = (string) ($_GET['token'] ?? '');
        $this->renderConfirmForm($token);
    }

    public function confirm(): void
    {
        $token    = (string) ($_POST['token'] ?? '');
        $password = (string) ($_POST['password'] ?? '');
        $confirm  = (string) ($_POST['password_confirm'] ?? '');

        if ($password !== $confirm) {
            $this->renderConfirmForm($token, 'Passwords do not match.');

            return;
        }

        if (!$this->hasher->meetsLengthPolicy($password)) {
            $this->renderConfirmForm(
                $token,
                sprintf('Password must be %d–%d characters.', PasswordHasher::MIN_LENGTH, PasswordHasher::MAX_LENGTH)
            );

            return;
        }

        try {
            $userId = $this->resets->consume($token, $this->hasher->hash($password));
        } catch (AuthException $e) {
            View::render('Password reset', '<h1>Password reset</h1><p class="error">' . View::e($e->getMessage()) . '</p>', null);

            return;
        }

        // Reset consumes the token, invalidates all existing sessions, and
        // never bypasses the second factor — the next login still requires
        // it (spec §15.4).
        $this->sessions->destroyAllForUser($userId);
        $this->audit->record($userId, 'password_reset.completed', (string) $userId, [], $this->clientIp());

        $body = '<div class="narrow"><div class="card">'
            . '<h2>Password reset</h2>'
            . '<p class="card-sub">Your password has been changed. You\'ll still need your second factor to sign in.</p>'
            . '<a href="/login" class="btn btn-primary btn-block">Log in</a>'
            . '</div></div>';
        View::render('Password reset', $body, null);
    }

    private function renderRequestForm(): void
    {
        $body = '<div class="narrow"><div class="card">'
            . '<h2>Reset your password</h2>'
            . '<p class="card-sub">We\'ll email a link if that address has an account.</p>'
            . '<form method="post" action="/password-reset">'
            . '<div class="field"><label for="email">Email</label>'
            . '<input type="email" id="email" name="email" required autofocus autocomplete="email"></div>'
            . '<button type="submit" class="btn btn-primary btn-block">Send reset link</button>'
            . '</form></div></div>';
        View::render('Password reset', $body, null);
    }

    private function renderConfirmForm(string $token, ?string $error = null): void
    {
        $body = '<div class="narrow"><div class="card">'
            . '<h2>Set a new password</h2>';

        if ($error !== null) {
            $body .= '<p class="error">' . View::e($error) . '</p>';
        }

        $body .= '<form method="post" action="/password-reset/confirm">'
            . '<input type="hidden" name="token" value="' . View::e($token) . '">'
            . '<div class="field"><label for="password">New password</label>'
            . '<input type="password" id="password" name="password" minlength="' . PasswordHasher::MIN_LENGTH . '" required autofocus autocomplete="new-password"></div>'
            . '<div class="field"><label for="password_confirm">Confirm new password</label>'
            . '<input type="password" id="password_confirm" name="password_confirm" required autocomplete="new-password"></div>'
            . '<button type="submit" class="btn btn-primary btn-block">Set password</button>'
            . '</form></div></div>';
        View::render('Password reset', $body, null);
    }

    private function clientIp(): ?string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? null;

        return \is_string($ip) && $ip !== '' ? $ip : null;
    }
}
