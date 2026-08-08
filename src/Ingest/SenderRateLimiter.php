<?php

declare(strict_types=1);

namespace App\Ingest;

use DateTimeImmutable;
use PDO;

/**
 * Spec §4.1 — per-sender rate/volume caps. The rua address is public DNS, so
 * a single hostile sender could otherwise flood a run's processing budget
 * (parser-DoS) independent of the overall per-run batch_limit.
 *
 * Windows are fixed-size buckets keyed by (sender, window_start), incremented
 * atomically via INSERT ... ON DUPLICATE KEY UPDATE.
 */
final class SenderRateLimiter
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly int $windowMinutes,
        private readonly int $maxMessagesPerWindow,
    ) {
    }

    /** True if this sender is still within its cap for the current window. */
    public function allow(string $sender): bool
    {
        $sender      = strtolower(trim($sender)) ?: 'unknown';
        $windowStart = $this->currentWindowStart();

        $this->pdo->prepare(
            'INSERT INTO ingest_sender_counters (sender, window_start, message_count)
             VALUES (?, ?, 1)
             ON DUPLICATE KEY UPDATE message_count = message_count + 1'
        )->execute([$sender, $windowStart]);

        $stmt = $this->pdo->prepare(
            'SELECT message_count FROM ingest_sender_counters WHERE sender = ? AND window_start = ?'
        );
        $stmt->execute([$sender, $windowStart]);

        return (int) $stmt->fetchColumn() <= $this->maxMessagesPerWindow;
    }

    private function currentWindowStart(): string
    {
        $windowSeconds = max(60, $this->windowMinutes * 60);
        $bucket        = intdiv(time(), $windowSeconds) * $windowSeconds;

        return (new DateTimeImmutable('@' . $bucket))->format('Y-m-d H:i:s');
    }
}
