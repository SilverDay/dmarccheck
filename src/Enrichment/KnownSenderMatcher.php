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
 *
 * Two lookup methods, deliberately different in scope:
 *  - match() ignores known_senders.domain_id entirely — every rule applies,
 *    used by enrichment's system-wide ip_enrichment.label, which is
 *    informational, not a trust decision.
 *  - matchForDomain() respects domain_id (NULL = global, otherwise scoped)
 *    — required wherever "known sender" becomes a trust decision, e.g. the
 *    recommendation engine's known/unknown classification (spec §10.1): an
 *    IP known-good for domain A must not be treated as known for domain B
 *    just because some other domain vouched for it.
 */
final class KnownSenderMatcher
{
    /** @param list<array{ip_or_cidr: string, label: string, domain_id?: ?int}> $rules */
    public function __construct(private readonly array $rules)
    {
    }

    public static function fromDatabase(PDO $pdo): self
    {
        $stmt = $pdo->query('SELECT ip_or_cidr, label, domain_id FROM known_senders ORDER BY id');

        /** @var list<array{ip_or_cidr: string, label: string, domain_id: ?int}> $rules */
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

    public function matchForDomain(string $ip, int $domainId): ?string
    {
        foreach ($this->rules as $rule) {
            $ruleDomainId = $rule['domain_id'] ?? null;

            if ($ruleDomainId !== null && $ruleDomainId !== $domainId) {
                continue;
            }

            if (Ip::inCidr($ip, $rule['ip_or_cidr'])) {
                return $rule['label'];
            }
        }

        return null;
    }
}
