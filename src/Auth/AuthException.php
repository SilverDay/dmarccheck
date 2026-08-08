<?php

declare(strict_types=1);

namespace App\Auth;

/**
 * Marks an expected, user-facing auth failure (bad credentials, expired
 * token, last-super-admin protection, ...) — controllers catch this
 * specifically and show the message; anything else is a 500.
 */
final class AuthException extends \RuntimeException
{
}
