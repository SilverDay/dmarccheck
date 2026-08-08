<?php

declare(strict_types=1);

namespace App\Enrichment;

use App\Support\Ip;
use PDO;

/**
 * Persistence for `ip_enrichment` (spec §3.5/§6). Rows are seeded by
 * ReportStore::touchEnrichment() on ingest with only `last_seen` set —
 * this class finds the ones still needing a lookup and writes the result.
 */
final class IpEnrichmentRepository
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    /** @return list<string> IP address strings, never-enriched first */
    public function findDueForLookup(int $limit, int $refreshDays): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT source_ip FROM ip_enrichment
              WHERE lookup_at IS NULL OR lookup_at < NOW() - INTERVAL ? DAY
              ORDER BY lookup_at IS NOT NULL, lookup_at ASC
              LIMIT ?'
        );
        $stmt->bindValue(1, $refreshDays, PDO::PARAM_INT);
        $stmt->bindValue(2, $limit, PDO::PARAM_INT);
        $stmt->execute();

        return array_map(
            static fn (string $binary): string => Ip::toString($binary),
            $stmt->fetchAll(PDO::FETCH_COLUMN)
        );
    }

    public function save(string $ip, EnrichmentResult $result): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE ip_enrichment
                SET rdns = ?, asn = ?, asn_org = ?, label = ?, lookup_at = NOW()
              WHERE source_ip = ?'
        );

        $stmt->execute([
            $result->rdns,
            $result->asn,
            $result->asnOrg,
            $result->label,
            Ip::toBinary($ip),
        ]);
    }
}
