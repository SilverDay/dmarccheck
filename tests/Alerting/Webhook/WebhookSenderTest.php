<?php

declare(strict_types=1);

namespace App\Tests\Alerting\Webhook;

use App\Alerting\AlertFinding;
use App\Alerting\Webhook\WebhookDestination;
use App\Alerting\Webhook\WebhookHttpClient;
use App\Alerting\Webhook\WebhookHttpResponse;
use App\Alerting\Webhook\WebhookSender;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class WebhookSenderTest extends TestCase
{
    protected function tearDown(): void
    {
        putenv('DMARC_TEST_WEBHOOK_URL');
        putenv('DMARC_TEST_WEBHOOK_SECRET');
    }

    public function testSuccessSendsMinimalSignedPayload(): void
    {
        $http   = new FakeWebhookHttpClient([new WebhookHttpResponse(202)]);
        $sender = new WebhookSender($http, [
            $this->destination(str_repeat('s', 32)),
        ]);
        $finding = new AlertFinding(
            'unknown_volume',
            'example.com',
            'Contains source 192.0.2.1 and private evidence.',
            ['ip' => '192.0.2.1', 'count' => 80]
        );

        $results = $sender->send([$finding], new DateTimeImmutable('2026-11-02T18:00:00Z'));
        $request = $http->requests[0];
        $payload = json_decode($request['body'], true, flags: JSON_THROW_ON_ERROR);

        self::assertCount(1, $results);
        self::assertTrue($results[0]->success);
        self::assertSame(['type', 'domain', 'severity', 'timestamp', 'message'], array_keys($payload));
        self::assertSame('unknown_volume', $payload['type']);
        self::assertSame('medium', $payload['severity']);
        self::assertStringNotContainsString('192.0.2.1', $request['body']);
        self::assertStringNotContainsString('private evidence', $request['body']);
        self::assertSame(hash_hmac('sha256', $request['body'], str_repeat('s', 32)), $request['signature']);
        self::assertSame(3, $request['timeout']);
    }

    public function testRetriesTransientFailureWithSameEventIdAndStopsOnSuccess(): void
    {
        $http   = new FakeWebhookHttpClient([new WebhookHttpResponse(503), new WebhookHttpResponse(204)]);
        $sender = new WebhookSender($http, [
            $this->destination(str_repeat('s', 32)),
        ]);

        $results = $sender->send([$this->finding()]);

        self::assertTrue($results[0]->success);
        self::assertSame(2, $results[0]->attempts);
        self::assertSame([503, 204], $results[0]->httpStatuses);
        self::assertSame($http->requests[0]['event_id'], $http->requests[1]['event_id']);
    }

    public function testPermanentFailureIsNotRetriedAndDoesNotExposeSecretInResult(): void
    {
        $secret = str_repeat('top-secret-', 4);
        $http   = new FakeWebhookHttpClient([new WebhookHttpResponse(400)]);
        $sender = new WebhookSender($http, [
            $this->destination($secret),
        ]);

        $results = $sender->send([$this->finding()]);

        self::assertFalse($results[0]->success);
        self::assertSame(1, $results[0]->attempts);
        self::assertStringNotContainsString($secret, json_encode($results[0], JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString($secret, $results[0]->destination);
    }

    public function testEachRunRealertsWithANewEventId(): void
    {
        $http = new FakeWebhookHttpClient([
            new WebhookHttpResponse(200),
            new WebhookHttpResponse(200),
        ]);
        $sender = new WebhookSender($http, [
            $this->destination(str_repeat('s', 32)),
        ]);

        $first  = $sender->send([$this->finding()]);
        $second = $sender->send([$this->finding()]);

        self::assertCount(1, $first);
        self::assertCount(1, $second);
        self::assertNotSame($first[0]->eventId, $second[0]->eventId);
        self::assertCount(2, $http->requests);
    }

    private function finding(): AlertFinding
    {
        return new AlertFinding('heartbeat', 'example.com', 'No report data.', []);
    }

    private function destination(string $secret): WebhookDestination
    {
        putenv('DMARC_TEST_WEBHOOK_URL=https://hooks.example.test/alerts');
        putenv('DMARC_TEST_WEBHOOK_SECRET=' . $secret);

        return WebhookDestination::fromEnvironment([
            'name'       => 'ops',
            'url_env'    => 'DMARC_TEST_WEBHOOK_URL',
            'secret_env' => 'DMARC_TEST_WEBHOOK_SECRET',
        ]);
    }
}

/** @internal */
final class FakeWebhookHttpClient implements WebhookHttpClient
{
    /** @var list<array{url: string, body: string, signature: string, event_id: string, timeout: int}> */
    public array $requests = [];

    /** @param list<WebhookHttpResponse> $responses */
    public function __construct(private array $responses)
    {
    }

    public function post(
        string $url,
        string $body,
        string $signature,
        string $eventId,
        int $timeoutSeconds,
    ): WebhookHttpResponse {
        $this->requests[] = [
            'url'       => $url,
            'body'      => $body,
            'signature' => $signature,
            'event_id'  => $eventId,
            'timeout'   => $timeoutSeconds,
        ];

        return array_shift($this->responses) ?? new WebhookHttpResponse(null);
    }
}
