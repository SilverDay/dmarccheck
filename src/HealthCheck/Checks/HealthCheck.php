<?php

declare(strict_types=1);

namespace App\HealthCheck\Checks;

use App\HealthCheck\HealthCheckItemResult;

interface HealthCheck
{
    /** @return list<HealthCheckItemResult> */
    public function run(string $domain): array;
}
