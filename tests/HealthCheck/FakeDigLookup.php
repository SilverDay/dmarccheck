<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck;

use App\HealthCheck\DigLookup;

/** @internal test double for DigLookup */
final class FakeDigLookup implements DigLookup
{
    /** @param array<string, list<string>|null> $answers "$name:$type" => answer (null = query error) */
    public function __construct(private readonly array $answers = [])
    {
    }

    public function query(string $name, string $type): ?array
    {
        $key = "$name:$type";

        if (!\array_key_exists($key, $this->answers)) {
            return [];
        }

        return $this->answers[$key];
    }
}
