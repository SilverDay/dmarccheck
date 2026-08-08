<?php

declare(strict_types=1);

namespace App\Recommendation\Rules;

use App\Recommendation\AnalysisContext;
use App\Recommendation\RuleFinding;

interface Rule
{
    /** @return list<RuleFinding> */
    public function evaluate(AnalysisContext $context): array;
}
