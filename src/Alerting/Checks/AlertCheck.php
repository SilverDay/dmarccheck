<?php

declare(strict_types=1);

namespace App\Alerting\Checks;

use App\Alerting\AlertContext;
use App\Alerting\AlertFinding;

interface AlertCheck
{
    /** @return list<AlertFinding> */
    public function evaluate(AlertContext $context): array;
}
