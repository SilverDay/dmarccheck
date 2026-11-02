<?php

declare(strict_types=1);

namespace App\Alerting\Webhook;

use InvalidArgumentException;

final readonly class WebhookDestination
{
    private function __construct(
        public string $name,
        public string $url,
        public string $secret,
    ) {
    }

    /**
     * Config stores environment-variable names, never endpoint credentials.
     *
     * @param array<string, mixed> $config
     */
    public static function fromEnvironment(array $config): self
    {
        $name      = $config['name']       ?? null;
        $urlEnv    = $config['url_env']    ?? null;
        $secretEnv = $config['secret_env'] ?? null;

        if (!\is_string($name) || preg_match('/^[a-zA-Z0-9_-]{1,64}$/D', $name)           !== 1
                               || !\is_string($urlEnv) || preg_match('/^[A-Z_][A-Z0-9_]*$/D', $urlEnv)       !== 1
                               || !\is_string($secretEnv) || preg_match('/^[A-Z_][A-Z0-9_]*$/D', $secretEnv) !== 1) {
            throw new InvalidArgumentException('Webhook configuration requires a valid name and environment-variable names.');
        }

        $url    = getenv($urlEnv);
        $secret = getenv($secretEnv);

        if ($url === false || $secret === false || $secret === '') {
            throw new InvalidArgumentException("Webhook environment variables $urlEnv and $secretEnv must be set.");
        }

        if (strlen($secret) < 32) {
            throw new InvalidArgumentException("Webhook secret in $secretEnv must contain at least 32 bytes.");
        }

        $parts = parse_url($url);

        if (filter_var($url, FILTER_VALIDATE_URL) === false
            || !\is_array($parts)
            || strtolower((string) ($parts['scheme'] ?? '')) !== 'https'
            || !isset($parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])
            || (isset($parts['port']) && $parts['port'] !== 443)
            || preg_match('/[\r\n]/', $url) === 1) {
            throw new InvalidArgumentException("Webhook URL in $urlEnv must be an HTTPS URL on port 443 without credentials, query, or fragment.");
        }

        return new self($name, $url, $secret);
    }
}
