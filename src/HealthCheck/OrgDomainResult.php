<?php

declare(strict_types=1);

namespace App\HealthCheck;

/** Result of `OrgDomain::resolve()` (RFC 9989 §4.10/§4.10.2 DNS Tree Walk). */
final readonly class OrgDomainResult
{
    /** @param list<string> $queriedNames every `_dmarc.<x>` name queried, in order — evidence for the walk taken */
    public function __construct(
        public ?string $organizationalDomain,
        public ?DmarcRecord $record,
        public string $discoveryMethod,
        public array $queriedNames,
    ) {
    }
}
