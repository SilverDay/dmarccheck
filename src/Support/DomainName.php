<?php

declare(strict_types=1);

namespace App\Support;

/**
 * Validates domain names accepted at onboarding (spec §11.1) — the string
 * ends up in live DNS/SMTP lookups (`HealthCheckRunnerFactory`), so this is
 * stricter than "looks vaguely like a hostname".
 */
final class DomainName
{
    private const string PATTERN = '/^(?=.{1,255}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i';

    public static function isValid(string $domain): bool
    {
        return preg_match(self::PATTERN, $domain) === 1;
    }
}
