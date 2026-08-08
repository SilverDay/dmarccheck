<?php

declare(strict_types=1);

namespace App\Auth;

use PDO;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\CertificateTrustPath;
use Webauthn\TrustPath\EmptyTrustPath;
use Webauthn\TrustPath\TrustPath;

/**
 * Maps webauthn-lib's CredentialRecord to/from the `webauthn_credentials`
 * row. Only `EmptyTrustPath` and `CertificateTrustPath` are handled — the
 * only trust paths reachable given the app only registers the 'none'
 * attestation statement format (see WebauthnService).
 */
final class WebauthnCredentialStore
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function findByCredentialId(string $rawCredentialId): ?CredentialRecord
    {
        $stmt = $this->pdo->prepare('SELECT * FROM webauthn_credentials WHERE credential_id = ?');
        $stmt->execute([$rawCredentialId]);
        $row = $stmt->fetch();

        return $row === false ? null : $this->toRecord($row);
    }

    /** @return list<CredentialRecord> */
    public function findAllForUser(int $userId): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM webauthn_credentials WHERE user_id = ?');
        $stmt->execute([$userId]);

        return array_map($this->toRecord(...), $stmt->fetchAll());
    }

    public function countForUser(int $userId): int
    {
        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?');
        $stmt->execute([$userId]);

        return (int) $stmt->fetchColumn();
    }

    /**
     * @return list<array{id: int, label: ?string, created_at: string, last_used_at: ?string}>
     */
    public function listForDisplay(int $userId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, label, created_at, last_used_at FROM webauthn_credentials
              WHERE user_id = ? ORDER BY created_at'
        );
        $stmt->execute([$userId]);

        /** @var list<array{id: int, label: ?string, created_at: string, last_used_at: ?string}> */
        return $stmt->fetchAll();
    }

    public function save(int $userId, CredentialRecord $record, ?string $label = null): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO webauthn_credentials
                (user_id, credential_id, public_key, sign_count, label,
                 attestation_type, aaguid, trust_path, transports, last_used_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
             ON DUPLICATE KEY UPDATE
                public_key = VALUES(public_key), sign_count = VALUES(sign_count),
                attestation_type = VALUES(attestation_type), aaguid = VALUES(aaguid),
                trust_path = VALUES(trust_path), transports = VALUES(transports),
                last_used_at = NOW()'
        );

        $stmt->execute([
            $userId,
            $record->publicKeyCredentialId,
            $record->credentialPublicKey,
            $record->counter,
            $label,
            $record->attestationType,
            $record->aaguid->toRfc4122(),
            json_encode($this->trustPathToArray($record->trustPath), JSON_THROW_ON_ERROR),
            json_encode($record->transports, JSON_THROW_ON_ERROR),
        ]);
    }

    public function updateSignCount(string $rawCredentialId, int $signCount): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE webauthn_credentials SET sign_count = ?, last_used_at = NOW() WHERE credential_id = ?'
        );
        $stmt->execute([$signCount, $rawCredentialId]);
    }

    public function remove(int $userId, int $credentialRowId): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?');
        $stmt->execute([$credentialRowId, $userId]);
    }

    /** @param array<string, mixed> $row */
    private function toRecord(array $row): CredentialRecord
    {
        /** @var array{class: string, certificates?: list<string>} $trustPathJson */
        $trustPathJson = json_decode((string) $row['trust_path'], true, flags: JSON_THROW_ON_ERROR);
        /** @var list<string> $transports */
        $transports = json_decode((string) $row['transports'], true, flags: JSON_THROW_ON_ERROR) ?? [];

        return new CredentialRecord(
            (string) $row['credential_id'],
            'public-key',
            $transports,
            (string) $row['attestation_type'],
            $this->trustPathFromArray($trustPathJson),
            Uuid::fromString((string) $row['aaguid']),
            (string) $row['public_key'],
            WebauthnUserHandle::forUser((int) $row['user_id']),
            (int) $row['sign_count'],
        );
    }

    /** @return array{class: string, certificates?: list<string>} */
    private function trustPathToArray(TrustPath $trustPath): array
    {
        return match (true) {
            $trustPath instanceof EmptyTrustPath       => ['class' => EmptyTrustPath::class],
            $trustPath instanceof CertificateTrustPath => [
                'class'        => CertificateTrustPath::class,
                'certificates' => $trustPath->certificates,
            ],
            default => throw new \RuntimeException('Unsupported trust path: ' . $trustPath::class),
        };
    }

    /** @param array{class: string, certificates?: list<string>} $data */
    private function trustPathFromArray(array $data): TrustPath
    {
        return match ($data['class'] ?? null) {
            EmptyTrustPath::class       => EmptyTrustPath::create(),
            CertificateTrustPath::class => CertificateTrustPath::create($data['certificates'] ?? []),
            default                     => throw new \RuntimeException('Unsupported stored trust path: ' . ($data['class'] ?? 'null')),
        };
    }
}
