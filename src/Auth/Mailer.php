<?php

declare(strict_types=1);

namespace App\Auth;

/**
 * Invitation/password-reset email delivery via PHP's mail() (local MTA) —
 * matches the project's minimal-dependency style; no SMTP config exists yet.
 */
final class Mailer
{
    public function __construct(private readonly string $fromAddress)
    {
    }

    public function send(string $toAddress, string $subject, string $body): bool
    {
        $toAddress = $this->stripHeaderInjection($toAddress);
        $subject   = $this->stripHeaderInjection($subject);

        $headers = [
            'From: ' . $this->stripHeaderInjection($this->fromAddress),
            'Content-Type: text/plain; charset=utf-8',
        ];

        return mail($toAddress, $subject, $body, implode("\r\n", $headers));
    }

    /** mail() headers are newline-delimited; strip anything that could inject one. */
    private function stripHeaderInjection(string $value): string
    {
        return trim(str_replace(["\r", "\n"], '', $value));
    }
}
