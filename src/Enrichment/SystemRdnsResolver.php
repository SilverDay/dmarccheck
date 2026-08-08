<?php

declare(strict_types=1);

namespace App\Enrichment;

/**
 * Wraps gethostbyaddr() (spec §6, option one — "gethostbyaddr() or async
 * batch resolution"). It has no per-call timeout in PHP; a single hung
 * resolver could stall a run. That's accepted here rather than engineered
 * around: enrichment already runs as a decoupled cron step precisely so a
 * slow DNS lookup never blocks ingestion, and bounding overall run time is
 * a cron-wrapper concern, not something an async DNS library solves for us.
 */
final class SystemRdnsResolver implements RdnsResolver
{
    public function resolve(string $ip): ?string
    {
        $host = @gethostbyaddr($ip);

        // gethostbyaddr() returns the unmodified input on failure — the only
        // way to detect "no PTR record" rather than a real success.
        if ($host === false || $host === $ip) {
            return null;
        }

        return $host;
    }
}
