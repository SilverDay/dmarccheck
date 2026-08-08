<?php

declare(strict_types=1);

namespace App\HealthCheck;

/**
 * One row of `health_check_items` (spec §11.3). `error` is deliberately a
 * distinct status from `fail` — a DNS timeout or an unconfigured blocklist
 * key is *unknown*, never reported as clean or as a confirmed problem.
 */
final readonly class HealthCheckItemResult
{
    public const string PASS  = 'pass';
    public const string WARN  = 'warn';
    public const string FAIL  = 'fail';
    public const string INFO  = 'info';
    public const string ERROR = 'error';

    /** @param array<string, mixed> $detail */
    public function __construct(
        public string $category,
        public string $checkName,
        public string $status,
        public array $detail = [],
    ) {
    }
}
