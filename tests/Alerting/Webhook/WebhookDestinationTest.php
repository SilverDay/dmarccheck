<?php

declare(strict_types=1);

namespace App\Tests\Alerting\Webhook;

use App\Alerting\Webhook\WebhookDestination;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class WebhookDestinationTest extends TestCase
{
    protected function tearDown(): void
    {
        putenv('DMARC_TEST_WEBHOOK_URL');
        putenv('DMARC_TEST_WEBHOOK_SECRET');
    }

    public function testLoadsHttpsEndpointAndSigningSecretFromEnvironment(): void
    {
        $secret = str_repeat('s', 32);
        putenv('DMARC_TEST_WEBHOOK_URL=https://hooks.example.test/alerts');
        putenv('DMARC_TEST_WEBHOOK_SECRET=' . $secret);

        $destination = WebhookDestination::fromEnvironment([
            'name'       => 'operations',
            'url_env'    => 'DMARC_TEST_WEBHOOK_URL',
            'secret_env' => 'DMARC_TEST_WEBHOOK_SECRET',
        ]);

        self::assertSame('operations', $destination->name);
        self::assertSame('https://hooks.example.test/alerts', $destination->url);
        self::assertSame($secret, $destination->secret);
    }

    public function testRejectsInsecureOrCredentialBearingUrlsWithoutEchoingTheValue(): void
    {
        $url = 'http://user:password@hooks.example.test/alerts?token=private';
        putenv('DMARC_TEST_WEBHOOK_URL=' . $url);
        putenv('DMARC_TEST_WEBHOOK_SECRET=' . str_repeat('s', 32));

        try {
            WebhookDestination::fromEnvironment([
                'name'       => 'operations',
                'url_env'    => 'DMARC_TEST_WEBHOOK_URL',
                'secret_env' => 'DMARC_TEST_WEBHOOK_SECRET',
            ]);
            self::fail('Expected insecure webhook URL to be rejected.');
        } catch (InvalidArgumentException $e) {
            self::assertStringNotContainsString('password', $e->getMessage());
            self::assertStringNotContainsString('private', $e->getMessage());
        }
    }

    public function testRejectsWeakSigningSecrets(): void
    {
        putenv('DMARC_TEST_WEBHOOK_URL=https://hooks.example.test/alerts');
        putenv('DMARC_TEST_WEBHOOK_SECRET=short');

        $this->expectException(InvalidArgumentException::class);
        WebhookDestination::fromEnvironment([
            'name'       => 'operations',
            'url_env'    => 'DMARC_TEST_WEBHOOK_URL',
            'secret_env' => 'DMARC_TEST_WEBHOOK_SECRET',
        ]);
    }
}
