<?php

declare(strict_types=1);

namespace App\HealthCheck\Fix;

/** Pure, testable — mirrors TlsRptCheck::run()'s two-state detail shape (present vs. not). */
final class TlsRptFixSuggester
{
    /**
     * @param array<string, mixed> $detail TlsRptCheck::run()'s HealthCheckItemResult::$detail
     *
     * @return list<HealthCheckFix>
     */
    public static function suggest(string $domain, array $detail, string $mailFrom): array
    {
        $reason = isset($detail['reason']) && \is_string($detail['reason']) ? $detail['reason'] : null;

        if ($reason !== 'no TLS-RPT record published') {
            return [];
        }

        return [new HealthCheckFix(
            'DNS TXT record at _smtp._tls.' . $domain,
            '_smtp._tls.' . $domain,
            'TXT',
            'v=TLSRPTv1; rua=mailto:' . $mailFrom,
            'Requests reports when other mail servers fail to deliver to you over a secure (STARTTLS/MTA-STS) connection — visibility DMARC reports don\'t cover.',
        )];
    }
}
