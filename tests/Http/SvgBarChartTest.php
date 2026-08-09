<?php

declare(strict_types=1);

namespace App\Tests\Http;

use App\Http\SvgBarChart;
use PHPUnit\Framework\TestCase;

final class SvgBarChartTest extends TestCase
{
    public function testRendersAPlaceholderForEmptyData(): void
    {
        $html = SvgBarChart::render([]);

        self::assertStringContainsString('No report data yet', $html);
        self::assertStringNotContainsString('<svg', $html);
    }

    public function testRendersOneBarPerDay(): void
    {
        $html = SvgBarChart::render([
            ['day' => '2026-08-01', 'passed' => 90, 'failed' => 10],
            ['day' => '2026-08-02', 'passed' => 80, 'failed' => 20],
        ]);

        self::assertStringContainsString('<svg', $html);
        self::assertSame(4, substr_count($html, '<rect'));
    }

    public function testEscapesDayLabels(): void
    {
        $html = SvgBarChart::render([
            ['day' => '2026-08-01"><script>alert(1)</script>', 'passed' => 1, 'failed' => 0],
        ]);

        self::assertStringNotContainsString('<script>', $html);
    }

    public function testHandlesAZeroVolumeDayWithoutError(): void
    {
        $html = SvgBarChart::render([
            ['day' => '2026-08-01', 'passed' => 0, 'failed' => 0],
        ]);

        self::assertStringContainsString('<svg', $html);
    }
}
