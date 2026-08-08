<?php

declare(strict_types=1);

namespace App\Auth;

use PDO;

/**
 * Self-service password reset (spec §15.4). The controller must always show
 * the same "if that address exists, a link has been sent" response — this
 * class returns null for both "no such account" and "rate limited" so the
 * caller can't distinguish them either.
 */
final class PasswordResetService
{
    /** Cap on outstanding (unconsumed, unexpired) tokens per user — a simple
     *  rate limit that needs no extra schema (password_resets has no
     *  created_at to window against, only expires_at). */
    private const int MAX_OUTSTANDING = 3;

    public function __construct(
        private readonly PDO $pdo,
        private readonly UserRepository $users,
        private readonly int $ttlMinutes,
    ) {
    }

    /** @return string|null the raw token to email, or null (no account / rate-limited) */
    public function request(string $email): ?string
    {
        $user = $this->users->findByEmail($email);

        if ($user === null || !$user->isActive()) {
            return null;
        }

        $countStmt = $this->pdo->prepare(
            'SELECT COUNT(*) FROM password_resets
              WHERE user_id = ? AND consumed_at IS NULL AND expires_at > NOW()'
        );
        $countStmt->execute([$user->id]);

        if ((int) $countStmt->fetchColumn() >= self::MAX_OUTSTANDING) {
            return null;
        }

        $token     = bin2hex(random_bytes(32));
        $expiresAt = (new \DateTimeImmutable())->modify("+{$this->ttlMinutes} minutes");

        $stmt = $this->pdo->prepare(
            'INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)'
        );
        $stmt->execute([$user->id, hash('sha256', $token), $expiresAt->format('Y-m-d H:i:s')]);

        return $token;
    }

    /** @return int the user id whose password was reset */
    public function consume(string $rawToken, string $newCredentialHash): int
    {
        $stmt = $this->pdo->prepare('SELECT * FROM password_resets WHERE token_hash = ?');
        $stmt->execute([hash('sha256', $rawToken)]);
        $row = $stmt->fetch();

        if ($row === false || $row['consumed_at'] !== null) {
            throw new AuthException('This password reset link is invalid or has already been used.');
        }

        if (new \DateTimeImmutable((string) $row['expires_at']) < new \DateTimeImmutable()) {
            throw new AuthException('This password reset link has expired.');
        }

        $userId = (int) $row['user_id'];

        $this->pdo->prepare('UPDATE password_resets SET consumed_at = NOW() WHERE id = ?')->execute([$row['id']]);
        $this->users->updateCredentialHash($userId, $newCredentialHash);

        return $userId;
    }
}
