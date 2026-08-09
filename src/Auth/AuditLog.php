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

    /**
     * Most recent entries, newest first — the read half of this
     * previously insert-only class (SELECT was always intended, per the
     * class docblock). $actionPrefix (e.g. 'domain.%') serves the
     * dashboard's narrower recent-activity feed (spec §7.1); the full
     * Audit Log Viewer (spec §15.7) calls this unfiltered. Doesn't filter
     * on domain active state — an activity feed is historical by nature.
     *
     * @return list<AuditLogEntry>
     */
    public function recent(int $limit, ?string $actionPrefix = null): array
    {
        $sql = 'SELECT a.actor_user_id, a.action, a.target, a.detail_json, a.created_at, u.email AS actor_email
                  FROM audit_log a
                  LEFT JOIN users u ON u.id = a.actor_user_id';

        $params = [];

        if ($actionPrefix !== null) {
            $sql .= ' WHERE a.action LIKE ?';
            $params[] = $actionPrefix;
        }

        $sql .= ' ORDER BY a.created_at DESC LIMIT ?';

        $stmt = $this->pdo->prepare($sql);

        foreach ($params as $i => $param) {
            $stmt->bindValue($i + 1, $param);
        }

        $stmt->bindValue(\count($params) + 1, $limit, PDO::PARAM_INT);
        $stmt->execute();

        $entries = [];

        foreach ($stmt as $row) {
            /** @var mixed $detail */
            $detail = $row['detail_json'] !== null ? json_decode((string) $row['detail_json'], true) : [];

            $entries[] = new AuditLogEntry(
                $row['actor_user_id'] !== null ? (int) $row['actor_user_id'] : null,
                $row['actor_email']   !== null ? (string) $row['actor_email'] : null,
                (string) $row['action'],
                $row['target'] !== null ? (string) $row['target'] : null,
                \is_array($detail) ? $detail : [],
                (string) $row['created_at'],
            );
        }

        return $entries;
    }
}
