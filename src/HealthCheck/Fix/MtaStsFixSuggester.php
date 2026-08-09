<?php

declare(strict_types=1);

namespace App\HealthCheck\Fix;

/**
 * Pure, testable. MTA-STS needs two independent pieces (a DNS record and a
 * hosted HTTPS policy file) — generating only the DNS half would look like
 * a complete fix when it isn't, so this always returns both together, only
 * for the "nothing published yet" state. A DNS record already present but
 * an invalid/unreachable policy file (MtaStsCheck's FAIL/ERROR states) is a
 * webserver-hosting problem this can't meaningfully template.
 */
final class MtaStsFixSuggester
{
    /**
     * @param array<string, mixed> $detail MtaStsCheck::run()'s HealthCheckItemResult::$detail
     * @param list<string> $mxHosts this domain's own MX hostnames (MxCheck's detail, if available this run) — falls back to a placeholder when unknown
     *
     * @return list<HealthCheckFix>
     */
    public static function suggest(string $domain, array $detail, array $mxHosts = []): array
    {
        $reason = isset($detail['reason']) && \is_string($detail['reason']) ? $detail['reason'] : null;

        if ($reason !== 'no MTA-STS record published') {
            return [];
        }

        $id = gmdate('YmdHis');

        $mxLines     = $mxHosts !== [] ? $mxHosts : ['mail.yourdomain.tld'];
        $policyLines = ['version: STSv1', 'mode: testing'];

        foreach ($mxLines as $host) {
            $policyLines[] = 'mx: ' . $host;
        }

        $policyLines[] = 'max_age: 604800';

        return [
            new HealthCheckFix(
                'DNS TXT record at _mta-sts.' . $domain,
                '_mta-sts.' . $domain,
                'TXT',
                'v=STSv1; id=' . $id,
                'Step 1 of 2. The id changes whenever the policy below changes — receivers use it to know when to re-fetch.',
            ),
            new HealthCheckFix(
                'Policy file at https://mta-sts.' . $domain . '/.well-known/mta-sts.txt',
                'mta-sts.' . $domain . '/.well-known/mta-sts.txt',
                'FILE',
                implode("\n", $policyLines),
                'Step 2 of 2. Starts in "testing" mode (report-only, doesn\'t block delivery) — switch to "mode: enforce" once you\'ve confirmed it\'s working.'
                    . ($mxHosts === [] ? ' Replace mail.yourdomain.tld with your real mail server hostname(s).' : ''),
            ),
        ];
    }
}
