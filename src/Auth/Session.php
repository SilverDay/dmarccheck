<?php

declare(strict_types=1);

namespace App\Auth;

/** A resolved, live session: the raw cookie token and the user it belongs to. */
final readonly class Session
{
    public function __construct(
        public string $token,
        public int $userId,
    ) {
    }
}
