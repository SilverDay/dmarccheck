<?php

declare(strict_types=1);

namespace App\Alerting\Webhook;

final readonly class WebhookHttpResponse
{
    public function __construct(public ?int $statusCode)
    {
    }
}
