<?php

declare(strict_types=1);

namespace App\Http;

use App\Auth\AuthUser;
use App\Auth\Roles;

/**
 * Shared page shell — plain PHP echo, no templating engine, matching the
 * style already in public/index.php. Every page (auth or not) goes through
 * this so the nav/logout control is consistent and gated by role in one
 * place rather than duplicated per controller.
 *
 * Visual design: design-system/dmarc-analyzer/MASTER.md (ui-ux-pro-max).
 */
final class View
{
    /** @var array<string, array{icon: string}> */
    private const array BADGE_VARIANTS = [
        'success' => ['icon' => 'check-circle'],
        'warning' => ['icon' => 'alert-triangle'],
        'danger'  => ['icon' => 'x-circle'],
        'neutral' => ['icon' => 'minus-circle'],
        'unknown' => ['icon' => 'help-circle'],
    ];

    public static function render(
        string $title,
        string $bodyHtml,
        ?AuthUser $user,
        ?string $csrfToken = null,
        ?string $flash = null,
    ): void {
        header('Content-Type: text/html; charset=utf-8');

        echo '<!doctype html><html lang="en"><head><meta charset="utf-8">'
           . '<meta name="viewport" content="width=device-width, initial-scale=1">'
           . '<title>' . self::e($title) . ' — DMARC Analyzer</title>'
           . '<link rel="stylesheet" href="/assets/app.css">'
           . '<!-- must stay blocking, no defer/async — see public/assets/theme-init.js -->'
           . '<script src="/assets/theme-init.js"></script>'
           . '</head><body>';

        echo '<header class="topbar"><a class="brand" href="/">' . self::icon('shield') . 'DMARC Analyzer</a>';

        echo '<div class="topnav">';

        if ($user !== null) {
            echo '<a href="/">Domains</a>';

            if (Roles::atLeast($user->role, Roles::ADMIN)) {
                echo '<a href="/admin/known-senders">Allowlist</a>';
            }

            echo '<a href="/help">Help</a>';

            if (Roles::atLeast($user->role, Roles::SUPER_ADMIN)) {
                echo '<span class="topnav-admin">'
                   . '<a href="/admin/users">Users</a>'
                   . '<a href="/admin/audit-log">Audit log</a>'
                   . '</span>';
            }

            echo '<div class="who">'
               . '<a class="id" href="/account/security" title="Security settings"><span class="email">' . self::e($user->email) . '</span>'
               . '<span class="role">' . self::e(str_replace('_', ' ', $user->role)) . '</span></a>'
               . '<form method="post" action="/logout">'
               . self::csrfField($csrfToken)
               . '<button type="submit" class="logout-btn" title="Log out" aria-label="Log out">'
               . self::icon('logout') . '</button></form>'
               . '</div>';
        }

        echo self::themeToggle();
        echo '</div>';

        echo '</header>';

        echo '<main>';

        if ($flash !== null && $flash !== '') {
            echo '<p class="flash">' . self::e($flash) . '</p>';
        }

        echo $bodyHtml . '</main><script src="/assets/theme.js"></script></body></html>';
    }

    public static function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
    }

    public static function csrfField(?string $csrfToken): string
    {
        return $csrfToken === null
            ? ''
            : '<input type="hidden" name="csrf_token" value="' . self::e($csrfToken) . '">';
    }

    /** Inline reference into the shared sprite (public/assets/icons.svg) — never emoji. */
    public static function icon(string $id): string
    {
        return '<svg class="icon" aria-hidden="true"><use href="/assets/icons.svg#i-' . self::e($id) . '"/></svg>';
    }

    /**
     * A "?" trigger for the help-system tooltip (docs/feature-helpsystem.md
     * §4.1/§6.2) — public/assets/help.js wires the click, fetches
     * /help/inline?slug=, and renders the popover. Reuses the existing
     * help-circle icon rather than a literal "?" glyph, per this app's
     * SVG-only/no-emoji icon policy.
     */
    public static function helpTooltip(string $slug, string $ariaLabel): string
    {
        return '<button type="button" class="help-trigger" data-help-slug="' . self::e($slug) . '" aria-label="' . self::e($ariaLabel) . '">'
            . self::icon('help-circle') . '</button>';
    }

    /**
     * Light/dark toggle. Both icons are always rendered; app.css shows/hides
     * the right one off data-theme so it's correct from first paint with no
     * JS-timing dependency. public/assets/theme-init.js sets data-theme
     * before body paint (FOUC avoidance); public/assets/theme.js wires this
     * button's click and corrects aria-pressed/aria-label once loaded, since
     * the server can't know the stored localStorage preference. Builds its
     * own <svg> markup rather than calling self::icon() twice, so the CSS
     * class needed to distinguish/swap the two icons doesn't have to be
     * added to that method's output for every other of its call sites.
     */
    public static function themeToggle(): string
    {
        return '<button type="button" class="theme-toggle" aria-pressed="false" aria-label="Switch to dark theme">'
            . '<svg class="icon i-sun" aria-hidden="true"><use href="/assets/icons.svg#i-sun"/></svg>'
            . '<svg class="icon i-moon" aria-hidden="true"><use href="/assets/icons.svg#i-moon"/></svg>'
            . '</button>';
    }

    /**
     * A status badge: icon + text + color together, per the design system's
     * "never color alone" rule. $variant is one of success/warning/danger/
     * neutral/unknown.
     */
    public static function badge(string $variant, string $label): string
    {
        $icon = self::BADGE_VARIANTS[$variant]['icon'] ?? 'minus-circle';

        return '<span class="badge ' . self::e($variant) . '">' . self::icon($icon) . self::e($label) . '</span>';
    }
}
