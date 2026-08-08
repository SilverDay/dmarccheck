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

        $body = '<h1>Password reset</h1>'
            . '<p>If that address has an account, a reset link has been sent.</p>';
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

        $body = '<h1>Password reset</h1><p>Your password has been changed. <a href="/login">Log in</a> — you\'ll still need your second factor.</p>';
        View::render('Password reset', $body, null);
    }

    private function renderRequestForm(): void
    {
        $body = '<h1>Reset your password</h1>'
            . '<form method="post" action="/password-reset" class="stack">'
            . '<p><label for="email">Email</label>'
            . '<input type="email" id="email" name="email" required autofocus></p>'
            . '<p><button type="submit">Send reset link</button></p>'
            . '</form>';
        View::render('Password reset', $body, null);
    }

    private function renderConfirmForm(string $token, ?string $error = null): void
    {
        $body = '<h1>Set a new password</h1>';

        if ($error !== null) {
            $body .= '<p class="error">' . View::e($error) . '</p>';
        }

        $body .= '<form method="post" action="/password-reset/confirm" class="stack">'
            . '<input type="hidden" name="token" value="' . View::e($token) . '">'
            . '<p><label for="password">New password</label>'
            . '<input type="password" id="password" name="password" minlength="' . PasswordHasher::MIN_LENGTH . '" required autofocus></p>'
            . '<p><label for="password_confirm">Confirm new password</label>'
            . '<input type="password" id="password_confirm" name="password_confirm" required></p>'
            . '<p><button type="submit">Set password</button></p>'
            . '</form>';
        View::render('Password reset', $body, null);
    }

    private function clientIp(): ?string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? null;

        return \is_string($ip) && $ip !== '' ? $ip : null;
    }
}
