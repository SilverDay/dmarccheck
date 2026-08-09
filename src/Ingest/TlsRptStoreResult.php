<?php

declare(strict_types=1);

namespace App\Ingest;

/** Result of TlsRptStore::store() — a file can partially match managed domains. */
final readonly class TlsRptStoreResult
{
    /**
     * @param list<int>    $storedReportIds
     * @param list<string> $skippedDomains  unmanaged domains named in the file
     */
    public function __construct(
        public array $storedReportIds,
        public array $skippedDomains,
    ) {
    }
}
