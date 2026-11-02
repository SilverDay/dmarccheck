<?php

declare(strict_types=1);

namespace App\Alerting\Webhook;

use App\Alerting\AlertFinding;
use DateTimeImmutable;
use DateTimeZone;

final class WebhookSender
{
    private const int MAX_ATTEMPTS    = 3;
    private const int TIMEOUT_SECONDS = 3;

    /** @param list<WebhookDestination> $destinations */
    public function __construct(
        private readonly WebhookHttpClient $http,
        private readonly array $destinations,
    ) {
    }

    /**
     * Every current finding is sent on every run, matching the email digest's
     * intentional repeat-while-active semantics.
     *
     * @param list<AlertFinding> $findings
     *
     * @return list<WebhookDeliveryResult>
     */
    public function send(array $findings, ?DateTimeImmutable $now = null): array
    {
        if ($findings === [] || $this->destinations === []) {
            return [];
        }

        $timestamp = ($now ?? new DateTimeImmutable('now', new DateTimeZone('UTC')))
            ->setTimezone(new DateTimeZone('UTC'))
            ->format(DATE_ATOM);
        $results = [];

        foreach ($this->destinations as $destination) {
            foreach ($findings as $finding) {
                $payload = json_encode([
                    'type'      => $finding->type,
                    'domain'    => $finding->domain,
                    'severity'  => self::severity($finding->type),
                    'timestamp' => $timestamp,
                    'message'   => self::message($finding->type),
                ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
                $signature = hash_hmac('sha256', $payload, $destination->secret);
                $eventId   = bin2hex(random_bytes(16));
                $statuses  = [];
                $success   = false;

                for ($attempt = 1; $attempt <= self::MAX_ATTEMPTS; $attempt++) {
                    $response = $this->http->post(
                        $destination->url,
                        $payload,
                        $signature,
                        $eventId,
                        self::TIMEOUT_SECONDS
                    );
                    $statuses[] = $response->statusCode;

                    if ($response->statusCode !== null && $response->statusCode >= 200 && $response->statusCode < 300) {
                        $success = true;

                        break;
                    }

                    if (!self::isRetryable($response->statusCode) || $attempt === self::MAX_ATTEMPTS) {
                        break;
                    }

                    usleep($attempt * 100_000);
                }

                $results[] = new WebhookDeliveryResult(
                    $destination->name,
                    $finding->type,
                    $finding->domain,
                    $eventId,
                    $success,
                    \count($statuses),
                    $statuses,
                );
            }
        }

        return $results;
    }

    private static function isRetryable(?int $status): bool
    {
        return $status === null || $status === 408 || $status === 429 || $status >= 500;
    }

    private static function severity(string $type): string
    {
        return match ($type) {
            'heartbeat', 'policy_drift'              => 'high',
            'unknown_volume', 'pass_rate_regression' => 'medium',
            default                                  => 'info',
        };
    }

    private static function message(string $type): string
    {
        return match ($type) {
            'heartbeat'            => 'No DMARC aggregate reports were received within the configured heartbeat threshold.',
            'policy_drift'         => 'The published DMARC policy differs from the approved baseline.',
            'unknown_volume'       => 'Unknown-source message volume exceeded the configured threshold.',
            'pass_rate_regression' => 'The DMARC pass rate declined beyond the configured threshold.',
            default                => 'A DMARC alert condition was detected.',
        };
    }
}
