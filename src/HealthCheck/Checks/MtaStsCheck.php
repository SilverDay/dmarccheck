<?php

declare(strict_types=1);

namespace App\HealthCheck\Checks;

use App\HealthCheck\DnsResolver;
use App\HealthCheck\HealthCheckItemResult;

final class MtaStsCheck implements HealthCheck
{
    public function __construct(
        private readonly DnsResolver $dns,
        private readonly int $httpTimeoutSeconds = 5,
    ) {
    }

    public function run(string $domain): array
    {
        $txt     = $this->dns->txt('_mta-sts.' . $domain);
        $records = array_values(array_filter(
            $txt,
            static fn (string $t): bool => str_starts_with(strtolower(trim($t)), 'v=stsv1')
        ));

        if ($records === []) {
            return [new HealthCheckItemResult('dns', 'mta_sts', HealthCheckItemResult::INFO, [
                'reason' => 'no MTA-STS record published',
            ])];
        }

        $url  = "https://mta-sts.$domain/.well-known/mta-sts.txt";
        $body = $this->fetch($url);

        if ($body === null) {
            return [new HealthCheckItemResult('transport', 'mta_sts', HealthCheckItemResult::ERROR, [
                'reason' => 'DNS record present but the policy file fetch failed',
                'url'    => $url,
            ])];
        }

        $valid = str_starts_with(trim($body), 'version: STSv1');

        return [new HealthCheckItemResult(
            'transport',
            'mta_sts',
            $valid ? HealthCheckItemResult::PASS : HealthCheckItemResult::FAIL,
            ['url' => $url, 'reason' => $valid ? 'policy file valid' : 'policy file did not start with "version: STSv1"']
        )];
    }

    private function fetch(string $url): ?string
    {
        $context = stream_context_create([
            'http' => ['timeout' => $this->httpTimeoutSeconds, 'ignore_errors' => true],
            'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);

        $body = @file_get_contents($url, false, $context);

        if ($body === false) {
            return null;
        }

        /** @var list<string> $http_response_header */
        $statusLine = $http_response_header[0] ?? '';

        if (preg_match('/\s(2\d{2})\s/', $statusLine) !== 1) {
            return null;
        }

        return $body;
    }
}
