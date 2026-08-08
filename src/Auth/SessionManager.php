<?php

declare(strict_types=1);

namespace App\Auth;

use App\Support\Ip;
use PDO;

/**
 * Server-side sessions (spec §15.3) backed by the `sessions` table — not
 * PHP's native session mechanism. The cookie carries an opaque random
 * token; only its SHA-256 hash is stored (schema comment: "session id
 * hash"), so a DB leak doesn't hand out live session tokens. Storing the
 * session server-side (rather than a signed cookie) is what makes targeted
 * revocation possible: "force logout" and "disable user" are a single
 * `DELETE FROM sessions WHERE user_id = ?`.
 *
 * Both idle (`last_seen_at`) and absolute (`created_at`/`expires_at`)
 * timeouts are enforced on every lookup; either expiry deletes the row
 * rather than merely failing the check, so expired sessions don't linger.
 */
final class SessionManager
{
    private bool $resolved    = false;
    private ?Session $current = null;

    public function __construct(
        private readonly PDO $pdo,
        private readonly string $cookieName,
        private readonly int $idleMinutes,
        private readonly int $absoluteHours,
        private readonly bool $secureCookie,
    ) {
    }

    public function current(): ?Session
    {
        if ($this->resolved) {
            return $this->current;
        }

        $this->resolved = true;

        $token = $_COOKIE[$this->cookieName] ?? null;

        if (!\is_string($token) || $token === '') {
            return null;
        }

        $hash = hash('sha256', $token);
        $stmt = $this->pdo->prepare('SELECT * FROM sessions WHERE id = ?');
        $stmt->execute([$hash]);
        $row = $stmt->fetch();

        if ($row === false) {
            $this->clearCookie();

            return null;
        }

        $now          = new \DateTimeImmutable();
        $expiresAt    = new \DateTimeImmutable((string) $row['expires_at']);
        $idleDeadline = (new \DateTimeImmutable((string) $row['last_seen_at']))
            ->modify("+{$this->idleMinutes} minutes");

        if ($now > $expiresAt || $now > $idleDeadline) {
            $this->deleteRow($hash);
            $this->clearCookie();

            return null;
        }

        $this->pdo->prepare('UPDATE sessions SET last_seen_at = NOW() WHERE id = ?')->execute([$hash]);

        $this->current = new Session($token, (int) $row['user_id']);

        return $this->current;
    }

    public function create(int $userId, ?string $sourceIp, ?string $userAgent): Session
    {
        $token     = bin2hex(random_bytes(32));
        $hash      = hash('sha256', $token);
        $expiresAt = (new \DateTimeImmutable())->modify("+{$this->absoluteHours} hours");

        $stmt = $this->pdo->prepare(
            'INSERT INTO sessions (id, user_id, expires_at, source_ip, user_agent)
             VALUES (?, ?, ?, ?, ?)'
        );
        $stmt->execute([
            $hash,
            $userId,
            $expiresAt->format('Y-m-d H:i:s'),
            $sourceIp  !== null ? Ip::toBinary($sourceIp) : null,
            $userAgent !== null ? substr($userAgent, 0, 255) : null,
        ]);

        $this->setCookie($token, $expiresAt);

        $this->resolved = true;
        $this->current  = new Session($token, $userId);

        return $this->current;
    }

    public function destroy(): void
    {
        $session = $this->current();

        if ($session !== null) {
            $this->deleteRow(hash('sha256', $session->token));
        }

        $this->clearCookie();
        $this->current  = null;
        $this->resolved = true;
    }

    /** Admin "force logout" / disable / password reset — revoke every session for a user. */
    public function destroyAllForUser(int $userId): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM sessions WHERE user_id = ?');
        $stmt->execute([$userId]);
    }

    /** Self-service password change (§15.4) — keep the current session, kill the rest. */
    public function destroyOthersForUser(int $userId, string $exceptToken): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM sessions WHERE user_id = ? AND id != ?');
        $stmt->execute([$userId, hash('sha256', $exceptToken)]);
    }

    private function deleteRow(string $hash): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM sessions WHERE id = ?');
        $stmt->execute([$hash]);
    }

    private function setCookie(string $token, \DateTimeImmutable $expiresAt): void
    {
        setcookie($this->cookieName, $token, [
            'expires'  => $expiresAt->getTimestamp(),
            'path'     => '/',
            'secure'   => $this->secureCookie,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }

    private function clearCookie(): void
    {
        setcookie($this->cookieName, '', [
            'expires'  => 1,
            'path'     => '/',
            'secure'   => $this->secureCookie,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }
}
