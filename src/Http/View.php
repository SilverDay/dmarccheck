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
           . '<link rel="stylesheet" href="/assets/app.css"></head><body>';

        echo '<header class="topbar"><a class="brand" href="/">' . self::icon('shield') . 'DMARC Analyzer</a>';

        if ($user !== null) {
            echo '<div class="topnav">'
               . '<a href="/">Domains</a>'
               . '<a href="/account/security">Security</a>';

            if (Roles::atLeast($user->role, Roles::SUPER_ADMIN)) {
                echo '<a href="/admin/users">Users</a>';
            }

            echo '<div class="who">'
               . '<span class="id"><span class="email">' . self::e($user->email) . '</span>'
               . '<span class="role">' . self::e(str_replace('_', ' ', $user->role)) . '</span></span>'
               . '<form method="post" action="/logout">'
               . self::csrfField($csrfToken)
               . '<button type="submit" class="logout-btn" title="Log out" aria-label="Log out">'
               . self::icon('logout') . '</button></form>'
               . '</div></div>';
        }

        echo '</header>';

        echo '<main>';

        if ($flash !== null && $flash !== '') {
            echo '<p class="flash">' . self::e($flash) . '</p>';
        }

        echo $bodyHtml . '</main></body></html>';
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
