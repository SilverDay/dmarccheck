<?php

declare(strict_types=1);

namespace App\Auth;

/**
 * WebAuthn needs a stable, opaque per-user handle (the `user.id` field of a
 * PublicKeyCredentialUserEntity). Rather than add a schema column, it's
 * derived deterministically from the user id, so both credential
 * registration and the `webauthn_credentials` row reconstruction
 * (WebauthnCredentialStore) agree on it without storing it anywhere.
 */
final class WebauthnUserHandle
{
    public static function forUser(int $userId): string
    {
        return hash('sha256', 'user:' . $userId, true);
    }
}
