<?php

declare(strict_types=1);

namespace App\Auth;

use OTPHP\TOTP;

/**
 * RFC 6238 TOTP enrollment/verification (spec §15.3 password-user fallback).
 *
 * users.totp_secret is stored encrypted at rest (schema comment, §15.8) —
 * secretbox (XSalsa20-Poly1305) with a random nonce prefixed to the
 * ciphertext, keyed by app.totp_encryption_key. This key is distinct from
 * the CSRF csrf_secret (Csrf) — never reuse a key across purposes.
 */
final class TotpService
{
    private const int LEEWAY_SECONDS = 15;

    private readonly string $encryptionKey;

    public function __construct(string $base64EncryptionKey)
    {
        $key = base64_decode($base64EncryptionKey, true);

        if ($key === false || \strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new \RuntimeException('app.totp_encryption_key must be a base64-encoded 32-byte key');
        }

        $this->encryptionKey = $key;
    }

    /** @return array{secret: string, provisioningUri: string, encryptedSecret: string} */
    public function generate(string $accountLabel, string $issuer): array
    {
        $secret = TOTP::generate()->getSecret();

        return [
            'secret'          => $secret,
            'provisioningUri' => $this->provisioningUriFor($secret, $accountLabel, $issuer),
            'encryptedSecret' => $this->encrypt($secret),
        ];
    }

    /** Rebuilds the enrollment QR/URI for a not-yet-confirmed plaintext secret. */
    public function provisioningUriFor(string $secret, string $accountLabel, string $issuer): string
    {
        $totp = TOTP::createFromSecret($secret);
        $totp->setLabel($accountLabel);
        $totp->setIssuer($issuer);

        return $totp->getProvisioningUri();
    }

    public function verify(string $encryptedSecret, string $code): bool
    {
        return $this->verifyPlaintext($this->decrypt($encryptedSecret), $code);
    }

    /**
     * Like verify(), but returns the TOTP period counter (floor(time()/30))
     * on success so the caller can record it for replay protection (F-02),
     * or null on failure.
     */
    public function verifyGetPeriod(string $encryptedSecret, string $code): ?int
    {
        $code = trim($code);

        if ($code === '' || !ctype_digit($code)) {
            return null;
        }

        $totp = TOTP::createFromSecret($this->decrypt($encryptedSecret));

        if (!$totp->verify($code, null, self::LEEWAY_SECONDS)) {
            return null;
        }

        return (int) floor(time() / $totp->getPeriod());
    }

    /** For the brief pre-storage confirmation step during enrollment (see generate()). */
    public function verifyPlaintext(string $secret, string $code): bool
    {
        $code = trim($code);

        if ($code === '' || !ctype_digit($code)) {
            return false;
        }

        return TOTP::createFromSecret($secret)->verify($code, null, self::LEEWAY_SECONDS);
    }

    public function encrypt(string $secret): string
    {
        $nonce      = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($secret, $nonce, $this->encryptionKey);

        return base64_encode($nonce . $ciphertext);
    }

    private function decrypt(string $encryptedSecret): string
    {
        $raw = base64_decode($encryptedSecret, true);

        if ($raw === false || \strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            throw new \RuntimeException('Malformed encrypted TOTP secret');
        }

        $nonce      = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $secret     = sodium_crypto_secretbox_open($ciphertext, $nonce, $this->encryptionKey);

        if ($secret === false) {
            throw new \RuntimeException('Failed to decrypt TOTP secret');
        }

        return $secret;
    }
}
