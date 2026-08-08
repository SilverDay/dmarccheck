<?php

declare(strict_types=1);

namespace App\HealthCheck;

final class SystemDnsResolver implements DnsResolver
{
    public function txt(string $name): array
    {
        $records = @dns_get_record($name, DNS_TXT);

        if ($records === false) {
            return [];
        }

        $result = [];

        foreach ($records as $record) {
            if (isset($record['txt']) && \is_string($record['txt'])) {
                $result[] = $record['txt'];
            }
        }

        return $result;
    }

    public function mx(string $domain): array
    {
        $records = @dns_get_record($domain, DNS_MX);

        if ($records === false) {
            return [];
        }

        $result = [];

        foreach ($records as $record) {
            if (isset($record['target'], $record['pri']) && \is_string($record['target'])) {
                $result[] = new MxRecord((int) $record['pri'], rtrim($record['target'], '.'));
            }
        }

        usort($result, static fn (MxRecord $a, MxRecord $b): int => $a->preference <=> $b->preference);

        return $result;
    }

    public function a(string $name): array
    {
        return $this->addresses($name, DNS_A, 'ip');
    }

    public function aaaa(string $name): array
    {
        return $this->addresses($name, DNS_AAAA, 'ipv6');
    }

    /** @return list<string> */
    private function addresses(string $name, int $type, string $field): array
    {
        $records = @dns_get_record($name, $type);

        if ($records === false) {
            return [];
        }

        $result = [];

        foreach ($records as $record) {
            if (isset($record[$field]) && \is_string($record[$field])) {
                $result[] = $record[$field];
            }
        }

        return $result;
    }
}
