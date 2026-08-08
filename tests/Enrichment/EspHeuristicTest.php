<?php

declare(strict_types=1);

namespace App\Tests\Enrichment;

use App\Enrichment\EspHeuristic;
use PHPUnit\Framework\TestCase;

final class EspHeuristicTest extends TestCase
{
    public function testKnownAsnClassifies(): void
    {
        $heuristic = new EspHeuristic([15169 => 'Google', 8075 => 'Microsoft']);

        self::assertSame('Google', $heuristic->classify(15169));
        self::assertSame('Microsoft', $heuristic->classify(8075));
    }

    public function testUnknownAsnReturnsNull(): void
    {
        $heuristic = new EspHeuristic([15169 => 'Google']);

        self::assertNull($heuristic->classify(64512));
    }

    public function testNullAsnReturnsNull(): void
    {
        $heuristic = new EspHeuristic([15169 => 'Google']);

        self::assertNull($heuristic->classify(null));
    }
}
