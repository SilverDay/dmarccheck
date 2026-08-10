<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck;

use App\HealthCheck\DnsResolver;
use App\HealthCheck\MxRecord;

/** @internal test double for DnsResolver */
final class FakeDnsResolver implements DnsResolver
{
    /** @var list<string> every name passed to txt(), in call order — e.g. for asserting OrgDomain's query cap */
    public array $txtCalls = [];

    /**
     * @param array<string, list<string>> $txtRecords name => TXT values
     * @param array<string, list<MxRecord>> $mxRecords domain => MX records
     * @param array<string, list<string>> $aRecords name => IPv4 addresses
     * @param array<string, list<string>> $aaaaRecords name => IPv6 addresses
     */
    public function __construct(
        private readonly array $txtRecords = [],
        private readonly array $mxRecords = [],
        private readonly array $aRecords = [],
        private readonly array $aaaaRecords = [],
    ) {
    }

    public function txt(string $name): array
    {
        $this->txtCalls[] = $name;

        return $this->txtRecords[$name] ?? [];
    }

    public function mx(string $domain): array
    {
        return $this->mxRecords[$domain] ?? [];
    }

    public function a(string $name): array
    {
        return $this->aRecords[$name] ?? [];
    }

    public function aaaa(string $name): array
    {
        return $this->aaaaRecords[$name] ?? [];
    }
}
