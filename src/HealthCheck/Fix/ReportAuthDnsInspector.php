<?php

declare(strict_types=1);

namespace App\HealthCheck\Fix;

use App\HealthCheck\Checks\SpfCheck;
use App\HealthCheck\DnsResolver;
use App\Support\DomainName;

final class ReportAuthDnsInspector
{
    private const string SELECTOR_PATTERN = '/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/D';

    public function __construct(private readonly DnsResolver $dns)
    {
    }

    /**
     * @return array{status: string, record: ?string, records: list<string>, lookup_count: ?int, issues: list<string>, reason: ?string}
     */
    public function inspectSpf(string $domain): array
    {
        $domain = strtolower(rtrim(trim($domain), '.'));

        if (!DomainName::isValid($domain)) {
            return [
                'status'       => 'error',
                'record'       => null,
                'records'      => [],
                'lookup_count' => null,
                'issues'       => [],
                'reason'       => 'Invalid SPF identity domain; no DNS lookup was made.',
            ];
        }

        $result = (new SpfCheck($this->dns))->run($domain)[0];
        $record = isset($result->detail['record']) && \is_string($result->detail['record'])
            ? $result->detail['record']
            : null;
        $records = isset($result->detail['records']) && \is_array($result->detail['records'])
            ? array_values(array_filter($result->detail['records'], 'is_string'))
            : [];
        $issues = isset($result->detail['issues']) && \is_array($result->detail['issues'])
            ? array_values(array_filter($result->detail['issues'], 'is_string'))
            : [];
        $lookupCount = $result->detail['lookup_count'] ?? null;
        $reason      = $result->detail['reason']       ?? null;

        return [
            'status'       => $result->status,
            'record'       => $record,
            'records'      => $records,
            'lookup_count' => \is_int($lookupCount) ? $lookupCount : null,
            'issues'       => $issues,
            'reason'       => \is_string($reason) ? $reason : null,
        ];
    }

    /**
     * @return array{name: string, records: list<string>}|null
     */
    public function inspectDkim(string $domain, string $selector): ?array
    {
        $domain   = strtolower(rtrim(trim($domain), '.'));
        $selector = trim($selector);

        if (!DomainName::isValid($domain) || preg_match(self::SELECTOR_PATTERN, $selector) !== 1) {
            return null;
        }

        $name = $selector . '._domainkey.' . $domain;

        return ['name' => $name, 'records' => $this->dns->txt($name)];
    }
}
