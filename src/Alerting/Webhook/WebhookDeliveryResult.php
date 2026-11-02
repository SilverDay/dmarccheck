<?php

declare(strict_types=1);

namespace App\Alerting\Webhook;

final readonly class WebhookDeliveryResult
{
    /** @param list<?int> $httpStatuses */
    public function __construct(
        public string $destination,
        public string $eventType,
        public string $domain,
        public string $eventId,
        public bool $success,
        public int $attempts,
        public array $httpStatuses,
    ) {
    }
}
