<?php

declare(strict_types=1);

namespace App\Enrichment;

use MaxMind\Db\Reader;

/** Local MaxMind GeoLite2-ASN DB (spec §6) — avoids per-query third-party disclosure (§14). */
final class GeoLite2AsnLookup implements AsnLookup
{
    private readonly Reader $reader;

    public function __construct(string $databasePath)
    {
        $this->reader = new Reader($databasePath);
    }

    public function lookup(string $ip): ?AsnInfo
    {
        /** @var mixed $record */
        $record = $this->reader->get($ip);

        if (!\is_array($record)
            || !isset($record['autonomous_system_number'], $record['autonomous_system_organization'])
        ) {
            return null;
        }

        return new AsnInfo(
            (int) $record['autonomous_system_number'],
            (string) $record['autonomous_system_organization'],
        );
    }
}
