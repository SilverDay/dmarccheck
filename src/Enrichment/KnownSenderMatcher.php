<?php

declare(strict_types=1);

namespace App\Enrichment;

use App\Support\Ip;
use PDO;

/**
 * `known_senders` CIDR matching (spec §6, first labelling tier — checked
 * before the ASN heuristic). Takes an already-fetched rule set rather than
 * a PDO so the matching logic itself is unit-testable without a database;
 * fromDatabase() is what bin/enrich.php actually calls.
 */
final class KnownSenderMatcher
{
    /** @param list<array{ip_or_cidr: string, label: string}> $rules */
    public function __construct(private readonly array $rules)
    {
    }

    public static function fromDatabase(PDO $pdo): self
    {
        $stmt = $pdo->query('SELECT ip_or_cidr, label FROM known_senders ORDER BY id');

        /** @var list<array{ip_or_cidr: string, label: string}> $rules */
        $rules = $stmt->fetchAll();

        return new self($rules);
    }

    public function match(string $ip): ?string
    {
        foreach ($this->rules as $rule) {
            if (Ip::inCidr($ip, $rule['ip_or_cidr'])) {
                return $rule['label'];
            }
        }

        return null;
    }
}
