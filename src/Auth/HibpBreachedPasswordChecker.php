<?php

declare(strict_types=1);

namespace App\Auth;

/**
 * Checks candidate passwords against the HaveIBeenPwned Pwned Passwords
 * corpus via k-anonymity (spec §15.3, NIST SP 800-63B §5.1.1.2) — only a
 * 5-character SHA-1 prefix of the password is ever sent, never the
 * password or its full hash, and no API key is required.
 *
 * A lookup failure (network, timeout, API down) is never treated as a
 * confirmed breach — isBreached() returns false. Blocking account
 * creation/password changes because a third-party API had a blip would
 * be worse than occasionally letting one unchecked password through;
 * same "unknown is not a fail" posture HealthCheckItemResult::ERROR
 * encodes elsewhere in this app, just without a status to surface here.
 */
final class HibpBreachedPasswordChecker
{
    private const string RANGE_URL = 'https://api.pwnedpasswords.com/range/';

    public function __construct(private readonly int $timeoutSeconds = 3)
    {
    }

    public function isBreached(string $password): bool
    {
        $sha1   = strtoupper(sha1($password));
        $suffix = substr($sha1, 5);

        $body = $this->fetch(self::RANGE_URL . substr($sha1, 0, 5));

        return $body !== null && self::matchesSuffix($body, $suffix);
    }

    /** Pure parsing of the k-anonymity range response — testable without network. */
    public static function matchesSuffix(string $responseBody, string $suffix): bool
    {
        $trimmed = trim($responseBody);

        if ($trimmed === '') {
            return false;
        }

        foreach (preg_split('/\r\n|\n/', $trimmed) as $line) {
            if (explode(':', $line, 2)[0] === $suffix) {
                return true;
            }
        }

        return false;
    }

    private function fetch(string $url): ?string
    {
        $context = stream_context_create([
            'http' => ['timeout' => $this->timeoutSeconds, 'ignore_errors' => true],
            'ssl'  => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);

        $body = @file_get_contents($url, false, $context);

        if ($body === false) {
            return null;
        }

        /** @var list<string> $http_response_header */
        $statusLine = $http_response_header[0] ?? '';

        if (preg_match('/\s(2\d{2})\s/', $statusLine) !== 1) {
            return null;
        }

        return $body;
    }
}
