<?php

declare(strict_types=1);

namespace App\Auth;

use App\Support\Ip;
use PDO;

/**
 * Append-only audit trail (spec §15.7). The app is only ever granted
 * INSERT/SELECT on this table (see db/schema.sql comment) — there is no
 * update/delete method here by design.
 */
final class AuditLog
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    /** @param array<string, mixed> $detail */
    public function record(
        ?int $actorUserId,
        string $action,
        ?string $target,
        array $detail = [],
        ?string $sourceIp = null,
    ): void {
        $stmt = $this->pdo->prepare(
            'INSERT INTO audit_log (actor_user_id, action, target, detail_json, source_ip)
             VALUES (?, ?, ?, ?, ?)'
        );

        $stmt->execute([
            $actorUserId,
            $action,
            $target,
            $detail === [] ? null : json_encode($detail, JSON_THROW_ON_ERROR),
            $sourceIp !== null ? Ip::toBinary($sourceIp) : null,
        ]);
    }
}
