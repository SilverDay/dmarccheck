<?php

declare(strict_types=1);

namespace App\Ingest;

use RuntimeException;

/**
 * Spec §4.1 — hostile input handling.
 *
 * Reports arrive gzip- or zip-compressed from anyone on the internet. Two
 * rules drive this class:
 *
 *  1. Sniff magic bytes; never trust the filename or Content-Type. Vendors
 *     are inconsistent about both.
 *  2. Decompress through a *bounded stream*. Never inflate-then-check — that
 *     is exactly what a decompression bomb exploits.
 */
final class Decompressor
{
    private const MAGIC_GZIP = "\x1f\x8b";
    private const MAGIC_ZIP  = "PK\x03\x04";

    public function __construct(
        private readonly int $maxDecompressedBytes,
        private readonly int $maxZipEntries,
    ) {
    }

    /**
     * @throws RuntimeException on unknown format or size-cap breach
     */
    public function decompress(string $payload): string
    {
        return match (true) {
            str_starts_with($payload, self::MAGIC_GZIP) => $this->inflateGzip($payload),
            str_starts_with($payload, self::MAGIC_ZIP)  => $this->inflateZip($payload),
            // Some senders attach plain XML or JSON
            $this->sniffFormat($payload) !== null => $this->guardSize($payload),
            default                               => throw new RuntimeException('Unrecognised attachment format'),
        };
    }

    /**
     * Sniffs decompressed/plain content to tell a DMARC XML report from an
     * RFC 8460 TLS-RPT JSON report — gzip's magic bytes say nothing about
     * the inner format, so this can only run post-inflation (or on a plain,
     * uncompressed payload). Never trust the attachment filename/extension.
     */
    public function sniffFormat(string $payload): ?string
    {
        $trimmed = ltrim($payload);

        return match (true) {
            str_starts_with($trimmed, '<')                                   => 'xml',
            str_starts_with($trimmed, '{') || str_starts_with($trimmed, '[') => 'json',
            default                                                          => null,
        };
    }

    private function guardSize(string $data): string
    {
        if (strlen($data) > $this->maxDecompressedBytes) {
            throw new RuntimeException('Payload exceeds decompressed size cap');
        }

        return $data;
    }

    /**
     * Streamed inflate with a hard ceiling. inflate_add() is fed in chunks so
     * we can abort as soon as the output crosses the cap, rather than
     * materialising an unbounded string first.
     */
    private function inflateGzip(string $payload): string
    {
        $ctx = inflate_init(ZLIB_ENCODING_GZIP);
        if ($ctx === false) {
            throw new RuntimeException('Could not initialise gzip stream');
        }

        $out    = '';
        $offset = 0;
        $chunk  = 32768;

        while ($offset < strlen($payload)) {
            $slice = substr($payload, $offset, $chunk);
            $offset += $chunk;

            $piece = inflate_add($ctx, $slice, ZLIB_NO_FLUSH);
            if ($piece === false) {
                throw new RuntimeException('Corrupt gzip stream');
            }

            $out .= $piece;
            if (strlen($out) > $this->maxDecompressedBytes) {
                throw new RuntimeException('Decompression exceeded size cap (possible bomb)');
            }
        }

        $tail = inflate_add($ctx, '', ZLIB_FINISH);
        if ($tail === false) {
            throw new RuntimeException('Corrupt gzip stream (finish)');
        }

        return $this->guardSize($out . $tail);
    }

    private function inflateZip(string $payload): string
    {
        $tmp = tempnam(sys_get_temp_dir(), 'dmarc_');
        if ($tmp === false) {
            throw new RuntimeException('Could not allocate temp file');
        }

        try {
            file_put_contents($tmp, $payload);

            $zip = new \ZipArchive();
            if ($zip->open($tmp) !== true) {
                throw new RuntimeException('Could not open zip payload');
            }

            if ($zip->numFiles > $this->maxZipEntries) {
                $zip->close();
                throw new RuntimeException('Zip entry count exceeds cap');
            }

            // Trust the declared size only as an early reject; the real
            // guard is the post-read length check below.
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $stat = $zip->statIndex($i);
                if ($stat === false) {
                    continue;
                }

                if (($stat['size'] ?? 0) > $this->maxDecompressedBytes) {
                    $zip->close();
                    throw new RuntimeException('Zip entry declares oversized content');
                }

                $data = $zip->getFromIndex($i, $this->maxDecompressedBytes + 1);
                if ($data === false) {
                    continue;
                }

                if (strlen($data) > $this->maxDecompressedBytes) {
                    $zip->close();
                    throw new RuntimeException('Zip entry exceeded size cap (possible bomb)');
                }

                if ($this->sniffFormat($data) !== null) {
                    $zip->close();

                    return $data;
                }
            }

            $zip->close();
            throw new RuntimeException('No parseable report entry found in zip');
        } finally {
            @unlink($tmp);
        }
    }
}
