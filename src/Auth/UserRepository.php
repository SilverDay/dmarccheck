<?php

declare(strict_types=1);

namespace App\Auth;

use PDO;

/**
 * CRUD against `users` (spec §15.8). Enforces the "at least one active
 * super_admin must always exist" invariant (§15.1) at the point of mutation
 * rather than trusting callers to check first.
 */
final class UserRepository
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function findById(int $id): ?AuthUser
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE id = ?');
        $stmt->execute([$id]);
        $row = $stmt->fetch();

        return $row === false ? null : AuthUser::fromRow($row);
    }

    public function findByEmail(string $email): ?AuthUser
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE email = ?');
        $stmt->execute([strtolower(trim($email))]);
        $row = $stmt->fetch();

        return $row === false ? null : AuthUser::fromRow($row);
    }

    /** @return list<AuthUser> */
    public function all(): array
    {
        $stmt = $this->pdo->query('SELECT * FROM users ORDER BY email');

        return array_map(AuthUser::fromRow(...), $stmt->fetchAll());
    }

    /** Creates the (invited) user row; invitation issuance calls this. */
    public function create(string $email, string $role): int
    {
        $stmt = $this->pdo->prepare(
            "INSERT INTO users (email, role, status) VALUES (?, ?, 'invited')"
        );
        $stmt->execute([strtolower(trim($email)), $role]);

        return (int) $this->pdo->lastInsertId();
    }

    /** Invitation acceptance completes here, once every required factor is set up. */
    public function activate(int $id): void
    {
        $stmt = $this->pdo->prepare("UPDATE users SET status = 'active' WHERE id = ?");
        $stmt->execute([$id]);
    }

    public function updateCredentialHash(int $id, string $credentialHash): void
    {
        $stmt = $this->pdo->prepare('UPDATE users SET credential_hash = ? WHERE id = ?');
        $stmt->execute([$credentialHash, $id]);
    }

    public function updateTotpSecret(int $id, ?string $encryptedSecret): void
    {
        $stmt = $this->pdo->prepare('UPDATE users SET totp_secret = ? WHERE id = ?');
        $stmt->execute([$encryptedSecret, $id]);
    }

    public function touchLastLogin(int $id): void
    {
        $stmt = $this->pdo->prepare('UPDATE users SET last_login_at = NOW() WHERE id = ?');
        $stmt->execute([$id]);
    }

    /** @throws AuthException if this would leave zero active super admins */
    public function updateRole(int $id, string $newRole): void
    {
        $this->guardLastSuperAdmin($id, static fn (AuthUser $u): bool => $u->role !== $newRole);

        $stmt = $this->pdo->prepare('UPDATE users SET role = ? WHERE id = ?');
        $stmt->execute([$newRole, $id]);
    }

    /** @throws AuthException if this would leave zero active super admins */
    public function disable(int $id): void
    {
        $this->guardLastSuperAdmin($id, static fn (): bool => true);

        $stmt = $this->pdo->prepare("UPDATE users SET status = 'disabled' WHERE id = ?");
        $stmt->execute([$id]);
    }

    public function enable(int $id): void
    {
        $stmt = $this->pdo->prepare("UPDATE users SET status = 'active' WHERE id = ?");
        $stmt->execute([$id]);
    }

    /** @throws AuthException if this would leave zero active super admins */
    public function delete(int $id): void
    {
        $this->guardLastSuperAdmin($id, static fn (): bool => true);

        $stmt = $this->pdo->prepare('DELETE FROM users WHERE id = ?');
        $stmt->execute([$id]);
    }

    public function countActiveSuperAdmins(): int
    {
        $stmt = $this->pdo->query(
            "SELECT COUNT(*) FROM users WHERE role = 'super_admin' AND status = 'active'"
        );

        return (int) $stmt->fetchColumn();
    }

    /**
     * Refuses a mutation that would strip the last active super admin of
     * that status. $wouldChange decides whether the mutation actually
     * affects super-admin-ness for this user (e.g. a role change to the
     * same role, or a no-op, doesn't need the check).
     *
     * @param callable(AuthUser): bool $wouldChange
     */
    private function guardLastSuperAdmin(int $id, callable $wouldChange): void
    {
        $user = $this->findById($id);

        if ($user === null || $user->role !== Roles::SUPER_ADMIN || !$user->isActive()) {
            return;
        }

        if (!$wouldChange($user)) {
            return;
        }

        if ($this->countActiveSuperAdmins() <= 1) {
            throw new AuthException('At least one active super admin must always exist.');
        }
    }
}
