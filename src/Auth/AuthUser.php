<?php

declare(strict_types=1);

namespace App\Auth;

/** Read-only view of a `users` row (spec §15.8). */
final readonly class AuthUser
{
    public function __construct(
        public int $id,
        public string $email,
        public ?string $credentialHash,
        public ?string $totpSecretEncrypted,
        public string $role,
        public string $status,
        public \DateTimeImmutable $createdAt,
        public ?\DateTimeImmutable $lastLoginAt,
    ) {
    }

    public function hasTotp(): bool
    {
        return $this->totpSecretEncrypted !== null;
    }

    public function hasPassword(): bool
    {
        return $this->credentialHash !== null;
    }

    public function isActive(): bool
    {
        return $this->status === 'active';
    }

    /** @param array<string, mixed> $row */
    public static function fromRow(array $row): self
    {
        return new self(
            (int) $row['id'],
            (string) $row['email'],
            $row['credential_hash'] !== null ? (string) $row['credential_hash'] : null,
            $row['totp_secret']     !== null ? (string) $row['totp_secret'] : null,
            (string) $row['role'],
            (string) $row['status'],
            new \DateTimeImmutable((string) $row['created_at']),
            $row['last_login_at'] !== null ? new \DateTimeImmutable((string) $row['last_login_at']) : null,
        );
    }
}
