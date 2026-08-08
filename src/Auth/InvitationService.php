<?php

declare(strict_types=1);

namespace App\Auth;

use PDO;

/**
 * Invitation-only account creation (spec §15.2). Only a token hash is
 * stored; the raw token exists only in the email link. Reissuing a pending
 * invitation invalidates the prior token rather than leaving two live links.
 */
final class InvitationService
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly UserRepository $users,
        private readonly int $ttlHours,
    ) {
    }

    /** @return string the raw token — email it, never store or log it */
    public function issue(string $email, string $role, int $invitedByUserId): string
    {
        if (!Roles::isValid($role)) {
            throw new AuthException('Invalid role.');
        }

        $email    = strtolower(trim($email));
        $existing = $this->users->findByEmail($email);

        if ($existing !== null && $existing->status !== 'invited') {
            throw new AuthException('That email is already registered.');
        }

        $userId = $existing !== null ? $existing->id : $this->users->create($email, $role);

        if ($existing !== null && $existing->role !== $role) {
            $this->users->updateRole($userId, $role);
        }

        $this->invalidatePending($email);

        $token     = bin2hex(random_bytes(32));
        $expiresAt = (new \DateTimeImmutable())->modify("+{$this->ttlHours} hours");

        $stmt = $this->pdo->prepare(
            'INSERT INTO invitations (email, token_hash, role, invited_by, expires_at)
             VALUES (?, ?, ?, ?, ?)'
        );
        $stmt->execute([$email, hash('sha256', $token), $role, $invitedByUserId, $expiresAt->format('Y-m-d H:i:s')]);

        return $token;
    }

    /**
     * Read-only validity check, for a multi-step accept flow (password+TOTP
     * setup, or passkey registration) that needs to confirm the token is
     * still good *before* asking the browser to run a ceremony, without
     * spending the token until the flow actually completes.
     *
     * @return array{email: string, role: string, userId: int}
     */
    public function peek(string $rawToken): array
    {
        return $this->lookup($rawToken);
    }

    /**
     * Validates and consumes the token. Call only once the corresponding
     * credential setup has succeeded — the token cannot be used again after
     * this returns, so a failure after this point would strand the user.
     *
     * @return array{email: string, role: string, userId: int}
     */
    public function accept(string $rawToken): array
    {
        $result = $this->lookup($rawToken);

        $this->pdo->prepare('UPDATE invitations SET consumed_at = NOW() WHERE token_hash = ?')
            ->execute([hash('sha256', $rawToken)]);

        return $result;
    }

    /** @return array{email: string, role: string, userId: int} */
    private function lookup(string $rawToken): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM invitations WHERE token_hash = ?');
        $stmt->execute([hash('sha256', $rawToken)]);
        $row = $stmt->fetch();

        if ($row === false || $row['consumed_at'] !== null) {
            throw new AuthException('This invitation link is invalid or has already been used.');
        }

        if (new \DateTimeImmutable((string) $row['expires_at']) < new \DateTimeImmutable()) {
            throw new AuthException('This invitation link has expired.');
        }

        $user = $this->users->findByEmail((string) $row['email']);

        if ($user === null) {
            throw new AuthException('This invitation link is invalid.');
        }

        return ['email' => (string) $row['email'], 'role' => (string) $row['role'], 'userId' => $user->id];
    }

    private function invalidatePending(string $email): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE invitations SET consumed_at = NOW() WHERE email = ? AND consumed_at IS NULL'
        );
        $stmt->execute([$email]);
    }
}
