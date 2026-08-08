<?php

declare(strict_types=1);

namespace App;

use RuntimeException;

final class Config
{
    /** @param array<string, mixed> $values */
    private function __construct(private readonly array $values)
    {
    }

    public static function load(?string $path = null): self
    {
        $path ??= dirname(__DIR__) . '/config/config.php';

        if (!is_readable($path)) {
            throw new RuntimeException(
                "Config not found at $path — copy config/config.sample.php to config/config.php"
            );
        }

        /** @var array<string, mixed> $values */
        $values = require $path;

        return new self($values);
    }

    /** Dot-path lookup: $config->get('imap.host') */
    public function get(string $key, mixed $default = null): mixed
    {
        $cursor = $this->values;

        foreach (explode('.', $key) as $segment) {
            if (!is_array($cursor) || !array_key_exists($segment, $cursor)) {
                return $default;
            }
            $cursor = $cursor[$segment];
        }

        return $cursor;
    }

    public function require(string $key): mixed
    {
        $value = $this->get($key);

        if ($value === null || $value === '') {
            throw new RuntimeException("Missing required config key: $key");
        }

        return $value;
    }
}
