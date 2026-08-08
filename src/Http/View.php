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
 */
final class View
{
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

        echo '<header class="topbar"><a class="brand" href="/">DMARC Analyzer</a>';

        if ($user !== null) {
            echo '<nav>'
               . '<span class="who">' . self::e($user->email) . ' &middot; ' . self::e($user->role) . '</span>'
               . ' <a href="/account/security">Security</a>';

            if (Roles::atLeast($user->role, Roles::SUPER_ADMIN)) {
                echo ' <a href="/admin/users">Users</a>';
            }

            echo ' <form method="post" action="/logout" class="inline">'
               . self::csrfField($csrfToken)
               . '<button type="submit" class="link">Log out</button></form>'
               . '</nav>';
        }

        echo '</header>';

        if ($flash !== null && $flash !== '') {
            echo '<p class="flash">' . self::e($flash) . '</p>';
        }

        echo '<main>' . $bodyHtml . '</main></body></html>';
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
}
