<?php

declare(strict_types=1);

namespace App\Auth;

/**
 * Short-lived, tamper-proof, server-unstateful payloads carried in a cookie
 * for the two spots that need to correlate two requests before a real
 * session exists: the password->TOTP step of login, and WebAuthn ceremony
 * challenges (registration and login both happen before/without a
 * `sessions` row in the unauthenticated login case). Sealed with
 * sodium_crypto_secretbox under a key derived from app.app_secret, with a
 * `$purpose` tag mixed into the key derivation so a cookie sealed for one
 * purpose can't be replayed as another.
 */
final class SealedCookie
{
    private const int TTL_SECONDS = 300;

    public function __construct(
        private readonly string $appSecret,
        private readonly bool $secureCookie,
    ) {
    }

    /** @param array<string, mixed> $payload */
    public function setCookie(string $cookieName, string $purpose, array $payload): void
    {
        setcookie($cookieName, $this->seal($purpose, $payload, self::TTL_SECONDS), [
            'expires'  => time() + self::TTL_SECONDS,
            'path'     => '/',
            'secure'   => $this->secureCookie,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }

    /** @return array<string, mixed>|null */
    public function readCookie(string $cookieName, string $purpose): ?array
    {
        $sealed = $_COOKIE[$cookieName] ?? null;

        return \is_string($sealed) ? $this->open($purpose, $sealed) : null;
    }

    public function clearCookie(string $cookieName): void
    {
        setcookie($cookieName, '', [
            'expires'  => 1,
            'path'     => '/',
            'secure'   => $this->secureCookie,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }

    /** @param array<string, mixed> $payload */
    public function seal(string $purpose, array $payload, int $ttlSeconds): string
    {
        $payload['exp'] = time() + $ttlSeconds;
        $json           = json_encode($payload, JSON_THROW_ON_ERROR);

        $nonce      = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($json, $nonce, $this->deriveKey($purpose));

        return base64_encode($nonce . $ciphertext);
    }

    /** @return array<string, mixed>|null null when missing, tampered, wrong purpose, or expired */
    public function open(string $purpose, string $sealed): ?array
    {
        $raw = base64_decode($sealed, true);

        if ($raw === false || \strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            return null;
        }

        $nonce      = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $json       = sodium_crypto_secretbox_open($ciphertext, $nonce, $this->deriveKey($purpose));

        if ($json === false) {
            return null;
        }

        /** @var mixed $payload */
        $payload = json_decode($json, true);

        if (!\is_array($payload) || !isset($payload['exp']) || (int) $payload['exp'] < time()) {
            return null;
        }

        return $payload;
    }

    private function deriveKey(string $purpose): string
    {
        return sodium_crypto_generichash($purpose . ':' . $this->appSecret, '', SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }
}
