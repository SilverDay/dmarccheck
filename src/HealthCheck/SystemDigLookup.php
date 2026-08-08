<?php

declare(strict_types=1);

namespace App\HealthCheck;

/**
 * Shells out to `dig`. Exit-code semantics verified empirically against a
 * real resolver: dig exits 0 whether or not records were found (NXDOMAIN/
 * empty answer is still exit 0), and non-zero (9, in the observed timeout
 * case) when the query itself failed — that split is exactly the
 * error-vs-no-data distinction DigLookup needs to preserve.
 */
final class SystemDigLookup implements DigLookup
{
    public function __construct(
        private readonly string $resolver,
        private readonly int $timeoutSeconds = 5,
    ) {
    }

    public function query(string $name, string $type): ?array
    {
        $command = \sprintf(
            'dig +short +time=%d +tries=1 -t %s %s @%s 2>&1',
            $this->timeoutSeconds,
            escapeshellarg($type),
            escapeshellarg($name),
            escapeshellarg($this->resolver)
        );

        exec($command, $output, $exitCode);

        if ($exitCode !== 0) {
            return null;
        }

        return array_values(array_filter($output, static fn (string $line): bool => trim($line) !== ''));
    }
}
