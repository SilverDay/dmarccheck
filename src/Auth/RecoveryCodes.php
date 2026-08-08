<?php

declare(strict_types=1);

namespace App\Auth;

/**
 * Single-use MFA backup codes (spec §15.3/§15.4), hashed at rest like
 * passwords. Persistence (the `recovery_codes` table) is the caller's job —
 * this class only generates, hashes, and picks which stored row a submitted
 * code matches, so the matching logic is unit-testable without a database.
 */
final class RecoveryCodes
{
    private const string ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I/L

    public function __construct(private readonly PasswordHasher $hasher = new PasswordHasher())
    {
    }

    /** @return list<string> plaintext codes, shown to the user exactly once */
    public function generateSet(int $count): array
    {
        $codes = [];

        for ($i = 0; $i < $count; $i++) {
            $codes[] = $this->generateOne();
        }

        return $codes;
    }

    public function hash(string $code): string
    {
        return $this->hasher->hash($this->normalize($code));
    }

    /**
     * @param list<array{id: int, code_hash: string, consumed_at: ?string}> $rows unconsumed-or-not rows for the user
     *
     * @return int|null the row id to mark consumed, or null if no unconsumed row matches
     */
    public function findMatch(array $rows, string $submittedCode): ?int
    {
        $submittedCode = $this->normalize($submittedCode);

        foreach ($rows as $row) {
            if ($row['consumed_at'] !== null) {
                continue;
            }

            if ($this->hasher->verify($submittedCode, $row['code_hash'])) {
                return $row['id'];
            }
        }

        return null;
    }

    private function generateOne(): string
    {
        $raw            = '';
        $alphabetLength = \strlen(self::ALPHABET);

        for ($i = 0; $i < 10; $i++) {
            $raw .= self::ALPHABET[random_int(0, $alphabetLength - 1)];
        }

        return substr($raw, 0, 5) . '-' . substr($raw, 5);
    }

    private function normalize(string $code): string
    {
        return strtoupper(trim($code));
    }
}
