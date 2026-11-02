<?php

declare(strict_types=1);

namespace App\Alerting\Webhook;

interface WebhookHttpClient
{
    public function post(
        string $url,
        string $body,
        string $signature,
        string $eventId,
        int $timeoutSeconds,
    ): WebhookHttpResponse;
}
