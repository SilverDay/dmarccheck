<?php

declare(strict_types=1);

namespace App\Alerting\Webhook;

final class StreamWebhookHttpClient implements WebhookHttpClient
{
    public function post(
        string $url,
        string $body,
        string $signature,
        string $eventId,
        int $timeoutSeconds,
    ): WebhookHttpResponse {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => implode("\r\n", [
                    'Content-Type: application/json',
                    'Accept: application/json',
                    'X-DMARC-Signature: sha256=' . $signature,
                    'X-DMARC-Event-Id: ' . $eventId,
                ]),
                'content'         => $body,
                'timeout'         => $timeoutSeconds,
                'ignore_errors'   => true,
                'follow_location' => 0,
                'max_redirects'   => 0,
            ],
            'ssl' => [
                'verify_peer'      => true,
                'verify_peer_name' => true,
            ],
        ]);

        $http_response_header = [];
        $stream               = @fopen($url, 'r', false, $context);

        if ($stream === false && !isset($http_response_header[0])) {
            return new WebhookHttpResponse(null);
        }

        if (\is_resource($stream)) {
            fclose($stream);
        }

        if (preg_match('/\s([1-5][0-9]{2})\s/', $http_response_header[0] ?? '', $matches) !== 1) {
            return new WebhookHttpResponse(null);
        }

        return new WebhookHttpResponse((int) $matches[1]);
    }
}
