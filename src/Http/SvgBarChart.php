<?php

declare(strict_types=1);

namespace App\Http;

/**
 * Renders a pass/fail volume-over-time series as a plain inline `<svg>` —
 * no Chart.js, no client-side JS, no third-party dependency (spec §7.2 asks
 * for "Chart.js fed by a JSON endpoint"; this delivers the same visual with
 * none of the footprint, since the app has zero JS dependencies today).
 * Bar colors reference the page's own CSS custom properties
 * (`--status-success-fg`/`--status-danger-fg`) via `var()`, so an inline
 * SVG embedded in the page picks up the current theme automatically —
 * no colors are baked in here.
 */
final class SvgBarChart
{
    private const int WIDTH       = 640;
    private const int HEIGHT      = 160;
    private const int BAR_GAP     = 2;
    private const int LABEL_SPACE = 18;

    /** @param list<array{day: string, passed: int, failed: int}> $days */
    public static function render(array $days): string
    {
        if ($days === []) {
            return '<p class="chart-empty">No report data yet.</p>';
        }

        $maxTotal = 1;

        foreach ($days as $d) {
            $maxTotal = max($maxTotal, $d['passed'] + $d['failed']);
        }

        $plotHeight = self::HEIGHT - self::LABEL_SPACE;
        $barWidth   = self::WIDTH / \count($days);

        $bars       = '';
        $labelEvery = (int) max(1, ceil(\count($days) / 8));

        foreach ($days as $i => $d) {
            $total = $d['passed'] + $d['failed'];
            $x     = $i * $barWidth;

            $failedHeight = $total > 0 ? ($d['failed'] / $maxTotal) * $plotHeight : 0.0;
            $passedHeight = $total > 0 ? ($d['passed'] / $maxTotal) * $plotHeight : 0.0;
            $barW         = max(1.0, $barWidth - self::BAR_GAP);

            $bars .= sprintf(
                '<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" style="fill:var(--status-danger-fg)"><title>%s: %d failed</title></rect>',
                $x,
                $plotHeight - $failedHeight,
                $barW,
                $failedHeight,
                htmlspecialchars($d['day'], ENT_QUOTES),
                $d['failed'],
            );
            $bars .= sprintf(
                '<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" style="fill:var(--status-success-fg)"><title>%s: %d passed</title></rect>',
                $x,
                $plotHeight - $failedHeight - $passedHeight,
                $barW,
                $passedHeight,
                htmlspecialchars($d['day'], ENT_QUOTES),
                $d['passed'],
            );

            if ($i % $labelEvery === 0) {
                $bars .= sprintf(
                    '<text x="%.2f" y="%d" class="chart-label">%s</text>',
                    $x,
                    self::HEIGHT - 4,
                    htmlspecialchars(substr($d['day'], 5), ENT_QUOTES),
                );
            }
        }

        return sprintf(
            '<svg class="trend-chart" viewBox="0 0 %d %d" preserveAspectRatio="none" role="img" aria-label="Pass/fail volume over time">%s</svg>',
            self::WIDTH,
            self::HEIGHT,
            $bars,
        );
    }
}
