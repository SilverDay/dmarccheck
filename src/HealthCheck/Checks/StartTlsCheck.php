<?php

declare(strict_types=1);

namespace App\HealthCheck\Checks;

use App\HealthCheck\DnsResolver;
use App\HealthCheck\HealthCheckItemResult;

/**
 * spec §11.2 transport security + §11.4 "keep it lightweight, never
 * intrusive": connects to a single MX host (lowest preference only —
 * bounded, not every MX), negotiates STARTTLS, and lets OpenSSL's own
 * verify_peer + verify_peer_name handle chain-trust, expiry, and hostname
 * matching in one handshake rather than re-implementing certificate
 * validation by hand. A plain connect-EHLO-STARTTLS sequence only — no
 * relay testing or other intrusive probing, exactly what §11.4 rules out.
 */
final class StartTlsCheck implements HealthCheck
{
    public function __construct(
        private readonly DnsResolver $dns,
        private readonly int $timeoutSeconds = 5,
    ) {
    }

    public function run(string $domain): array
    {
        $mxRecords = $this->dns->mx($domain);

        if ($mxRecords === []) {
            return [new HealthCheckItemResult('transport', 'starttls', HealthCheckItemResult::ERROR, [
                'reason' => 'no MX records to test',
            ])];
        }

        $host   = $mxRecords[0]->host;
        $socket = @stream_socket_client("tcp://$host:25", $errno, $errstr, $this->timeoutSeconds);

        if ($socket === false) {
            return [new HealthCheckItemResult('transport', 'starttls', HealthCheckItemResult::ERROR, [
                'host'   => $host,
                'reason' => "could not connect on port 25: $errstr",
            ])];
        }

        stream_set_timeout($socket, $this->timeoutSeconds);

        try {
            return [$this->negotiate($socket, $host)];
        } finally {
            fclose($socket);
        }
    }

    /** @param resource $socket */
    private function negotiate($socket, string $host): HealthCheckItemResult
    {
        $banner = fgets($socket);

        if ($banner === false || !str_starts_with($banner, '220')) {
            return new HealthCheckItemResult('transport', 'starttls', HealthCheckItemResult::ERROR, [
                'host'   => $host,
                'reason' => 'no valid SMTP banner received',
            ]);
        }

        fwrite($socket, "EHLO healthcheck.invalid\r\n");
        $capabilities = $this->readMultilineResponse($socket);

        if (preg_match('/^250[- ]STARTTLS/mi', $capabilities) !== 1) {
            return new HealthCheckItemResult('transport', 'starttls', HealthCheckItemResult::FAIL, [
                'host'   => $host,
                'reason' => 'STARTTLS not offered',
            ]);
        }

        fwrite($socket, "STARTTLS\r\n");
        $response = fgets($socket);

        if ($response === false || !str_starts_with($response, '220')) {
            return new HealthCheckItemResult('transport', 'starttls', HealthCheckItemResult::FAIL, [
                'host'   => $host,
                'reason' => 'STARTTLS command rejected',
            ]);
        }

        stream_context_set_option($socket, 'ssl', 'capture_peer_cert', true);
        stream_context_set_option($socket, 'ssl', 'verify_peer', true);
        stream_context_set_option($socket, 'ssl', 'verify_peer_name', true);
        stream_context_set_option($socket, 'ssl', 'peer_name', $host);

        $crypto = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);

        if ($crypto !== true) {
            return new HealthCheckItemResult('transport', 'starttls', HealthCheckItemResult::FAIL, [
                'host'   => $host,
                'reason' => 'TLS negotiation or certificate verification failed (expired, hostname mismatch, or untrusted chain)',
            ]);
        }

        $params = stream_context_get_params($socket);
        /** @var \OpenSSLCertificate|null $cert */
        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        $info = $cert !== null ? openssl_x509_parse($cert) : false;

        return new HealthCheckItemResult('transport', 'starttls', HealthCheckItemResult::PASS, [
            'host'       => $host,
            'subject_cn' => \is_array($info) ? ($info['subject']['CN'] ?? null) : null,
            'valid_to'   => \is_array($info) && isset($info['validTo_time_t']) ? date('Y-m-d', (int) $info['validTo_time_t']) : null,
            'issuer'     => \is_array($info) ? ($info['issuer']['O'] ?? $info['issuer']['CN'] ?? null) : null,
        ]);
    }

    /** @param resource $socket */
    private function readMultilineResponse($socket): string
    {
        $buffer = '';

        while (($line = fgets($socket, 512)) !== false) {
            $buffer .= $line;

            if (preg_match('/^\d{3} /', $line) === 1 || !str_contains($line, '-')) {
                break;
            }
        }

        return $buffer;
    }
}
