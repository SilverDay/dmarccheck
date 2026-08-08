<?php

declare(strict_types=1);

namespace App\Auth;

/**
 * Synchronizer token derived from the session token, not stored anywhere —
 * defense-in-depth alongside the SameSite=Strict session cookie (see
 * SessionManager). A CSRF token is only ever meaningful alongside a live
 * session, so deriving it via HMAC avoids a separate storage/cleanup path.
 */
final class Csrf
{
    public function __construct(private readonly string $appSecret)
    {
    }

    public function token(string $sessionToken): string
    {
        return hash_hmac('sha256', $sessionToken, $this->appSecret);
    }

    public function verify(string $sessionToken, string $submittedToken): bool
    {
        return hash_equals($this->token($sessionToken), $submittedToken);
    }
}
