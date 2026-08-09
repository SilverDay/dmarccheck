<?php

declare(strict_types=1);

namespace App\Auth;

/** One `audit_log` row for display (spec §15.7, §7.1's recent-activity feed). */
final readonly class AuditLogEntry
{
    /** @param array<string, mixed> $detail */
    public function __construct(
        public ?int $actorUserId,
        public ?string $actorEmail,
        public string $action,
        public ?string $target,
        public array $detail,
        public string $createdAt,
        public ?string $sourceIp,
    ) {
    }
}
