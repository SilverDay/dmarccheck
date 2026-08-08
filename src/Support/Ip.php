<?php

declare(strict_types=1);

namespace App\Support;

/**
 * IPs are stored as VARBINARY(16) so v4 and v6 share one column and one index.
 */
final class Ip
{
    public static function toBinary(string $ip): string
    {
        $packed = @inet_pton($ip);

        if ($packed === false) {
            throw new \InvalidArgumentException("Not an IP address: $ip");
        }

        return $packed;
    }

    public static function toString(string $binary): string
    {
        $ip = @inet_ntop($binary);

        return $ip === false ? '(invalid)' : $ip;
    }

    /** CIDR match for the known_senders allowlist (§3.6). */
    public static function inCidr(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return @inet_pton($ip) === @inet_pton($cidr);
        }

        [$subnet, $bits] = explode('/', $cidr, 2);

        $ipBin     = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        $bits  = (int) $bits;
        $bytes = intdiv($bits, 8);
        $rem   = $bits % 8;

        if ($bytes > 0 && strncmp($ipBin, $subnetBin, $bytes) !== 0) {
            return false;
        }

        if ($rem === 0) {
            return true;
        }

        $mask = ~((1 << (8 - $rem)) - 1) & 0xFF;

        return (ord($ipBin[$bytes]) & $mask) === (ord($subnetBin[$bytes]) & $mask);
    }
}
