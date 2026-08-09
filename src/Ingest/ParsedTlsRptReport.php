<?php

declare(strict_types=1);

namespace App\Ingest;

/**
 * Immutable result of parsing one RFC 8460 report (spec §12). Unlike
 * ParsedReport, this isn't domain-singular: a TLS-RPT JSON file's
 * `policies[]` array can name multiple domains in one report.
 */
final readonly class ParsedTlsRptReport
{
    /**
     * @param list<array<string, mixed>> $policies  each: domain, policy_type,
     *        policy_string, mx_host, success_count, failure_count,
     *        failure_details (list<array<string, mixed>>)
     * @param list<string>               $warnings  skipped/malformed entries
     */
    public function __construct(
        public string $organizationName,
        public string $reportId,
        public \DateTimeImmutable $dateBegin,
        public \DateTimeImmutable $dateEnd,
        public array $policies,
        public array $warnings = [],
    ) {
    }

    public function policyCount(): int
    {
        return count($this->policies);
    }
}
