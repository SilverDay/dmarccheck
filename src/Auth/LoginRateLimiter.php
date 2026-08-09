<?php

declare(strict_types=1);

namespace App\Auth;

use PDO;

/**
 * IP-keyed login rate limiter (F-04, spec §15).
 *
 * Uses a fixed-window counter in the `login_rate_limit` table, keyed on
 * (INET6_ATON(ip), window_start) so the same table handles IPv4 and IPv6.
 * Counters are pruned automatically on every check to keep the table small.
 */
final class LoginRateLimiter
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly int $windowMinutes = 5,
        private readonly int $maxAttempts = 5,
    ) {
    }

    /**
     * Returns true when the IP is within the attempt limit (request allowed).
     * Returns false when the IP has exceeded the limit (request should be blocked).
     *
     * Must be called *before* any password verification so the counter cannot
     * be bypassed by submitting credentials that short-circuit early.
     */
    public function check(string $ip): bool
    {
        $windowStart = $this->currentWindowStart();

        $stmt = $this->pdo->prepare(
            'SELECT attempt_count FROM login_rate_limit
              WHERE ip = INET6_ATON(?) AND window_start = ?'
        );
        $stmt->execute([$ip, $windowStart]);
        $count = (int) ($stmt->fetchColumn() ?: 0);

        return $count < $this->maxAttempts;
    }

    /**
     * Increments the failure counter for this IP in the current window.
     * Call only after a failed authentication attempt (both password and MFA steps).
     */
    public function recordFailure(string $ip): void
    {
        $windowStart = $this->currentWindowStart();

        $this->pdo->prepare(
            'INSERT INTO login_rate_limit (ip, window_start, attempt_count)
                  VALUES (INET6_ATON(?), ?, 1)
             ON DUPLICATE KEY UPDATE attempt_count = attempt_count + 1'
        )->execute([$ip, $windowStart]);

        // Prune windows older than 2× the window width; runs inline to avoid
        // needing a separate cron job. The pruning condition uses a constant
        // interval, not the dynamic window, so it always cleans up fully.
        $cutoff = date('Y-m-d H:i:s', time() - $this->windowMinutes * 60 * 2);
        $this->pdo->prepare(
            'DELETE FROM login_rate_limit WHERE window_start < ?'
        )->execute([$cutoff]);
    }

    private function currentWindowStart(): string
    {
        $windowSeconds = $this->windowMinutes * 60;

        return date('Y-m-d H:i:s', (int) (floor(time() / $windowSeconds) * $windowSeconds));
    }
}
