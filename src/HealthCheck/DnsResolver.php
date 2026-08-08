<?php

declare(strict_types=1);

namespace App\HealthCheck;

/**
 * Used by every check where the OS's default-configured resolver is fine.
 * DigLookup is the separate primitive for checks that need a specific
 * resolver or a record type this interface doesn't expose.
 */
interface DnsResolver
{
    /** @return list<string> */
    public function txt(string $name): array;

    /** @return list<MxRecord> sorted by preference ascending */
    public function mx(string $domain): array;

    /** @return list<string> IPv4 addresses */
    public function a(string $name): array;

    /** @return list<string> IPv6 addresses */
    public function aaaa(string $name): array;
}
