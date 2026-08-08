<?php

declare(strict_types=1);

namespace App\Recommendation;

/** Parses `p=`/`sp=` out of a policy string and orders enforcement strength (used by R7/R8/R9/R11). */
final class PolicyLevel
{
    private const array VALID = ['none', 'quarantine', 'reject'];
    private const array ORDER = ['none' => 0, 'quarantine' => 1, 'reject' => 2];

    public static function extract(?string $policyString): ?string
    {
        return self::extractTag($policyString, 'p');
    }

    public static function extractSubdomainPolicy(?string $policyString): ?string
    {
        return self::extractTag($policyString, 'sp');
    }

    public static function isStricter(string $a, string $b): bool
    {
        return (self::ORDER[$a] ?? -1) > (self::ORDER[$b] ?? -1);
    }

    /** Same normalization the dashboard uses to compare policy strings for equality (public/index.php). */
    public static function normalize(string $policyString): string
    {
        return strtolower(preg_replace('/\s+/', '', $policyString) ?? '');
    }

    private static function extractTag(?string $policyString, string $tag): ?string
    {
        if ($policyString === null) {
            return null;
        }

        foreach (explode(';', $policyString) as $part) {
            $part = trim($part);

            if (str_starts_with($part, $tag . '=')) {
                $value = strtolower(trim(substr($part, \strlen($tag) + 1)));

                return \in_array($value, self::VALID, true) ? $value : null;
            }
        }

        return null;
    }
}
