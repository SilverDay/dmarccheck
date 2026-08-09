<?php

declare(strict_types=1);

namespace App\Tests;

use App\Ingest\Decompressor;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class DecompressorTest extends TestCase
{
    public function testInflatesGzip(): void
    {
        $d = new Decompressor(1024 * 1024, 16);
        self::assertSame('<xml/>', $d->decompress((string) gzencode('<xml/>')));
    }

    public function testAcceptsPlainXml(): void
    {
        $d = new Decompressor(1024 * 1024, 16);
        self::assertSame('<xml/>', $d->decompress('<xml/>'));
    }

    public function testAcceptsPlainJson(): void
    {
        $d = new Decompressor(1024 * 1024, 16);
        self::assertSame('{"a":1}', $d->decompress('{"a":1}'));
    }

    /** The gzip-inflate path has no XML-specific logic — this locks that in. */
    public function testInflatesGzipJson(): void
    {
        $d = new Decompressor(1024 * 1024, 16);
        self::assertSame('{"a":1}', $d->decompress((string) gzencode('{"a":1}')));
    }

    public function testSniffFormatDetectsXmlJsonAndNeither(): void
    {
        $d = new Decompressor(1024 * 1024, 16);

        self::assertSame('xml', $d->sniffFormat('<xml/>'));
        self::assertSame('json', $d->sniffFormat('{"a":1}'));
        self::assertSame('json', $d->sniffFormat('  [1,2]'));
        self::assertNull($d->sniffFormat('not a report'));
    }

    public function testRejectsUnknownFormat(): void
    {
        $d = new Decompressor(1024 * 1024, 16);
        $this->expectException(RuntimeException::class);
        $d->decompress("\x00\x01binary junk");
    }

    /** §4.1 — a small gzip that inflates past the ceiling must abort mid-stream. */
    public function testRejectsDecompressionBomb(): void
    {
        $bomb = (string) gzencode(str_repeat('A', 5 * 1024 * 1024));

        $d = new Decompressor(1024, 16);  // 1 KiB ceiling

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/size cap/i');
        $d->decompress($bomb);
    }

    public function testInflatesZip(): void
    {
        $d   = new Decompressor(1024 * 1024, 16);
        $zip = $this->buildZip(['report.xml' => '<xml/>']);

        self::assertSame('<xml/>', $d->decompress($zip));
    }

    public function testInflatesZipWithJsonEntry(): void
    {
        $d   = new Decompressor(1024 * 1024, 16);
        $zip = $this->buildZip(['report.json' => '{"a":1}']);

        self::assertSame('{"a":1}', $d->decompress($zip));
    }

    /** §4.1 — zip entry count must be capped independently of any size check. */
    public function testRejectsZipEntryCountCap(): void
    {
        $d   = new Decompressor(1024 * 1024, 2);  // cap: 2 entries
        $zip = $this->buildZip([
            'a.xml' => '<a/>',
            'b.xml' => '<b/>',
            'c.xml' => '<c/>',
        ]);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/entry count/i');
        $d->decompress($zip);
    }

    /**
     * §4.1 — zip-bomb defence: a single entry whose *declared* uncompressed
     * size alone exceeds the cap must be rejected before its content is
     * read, even though highly compressible content keeps the zip itself
     * tiny on disk.
     */
    public function testRejectsOversizedZipEntry(): void
    {
        $d   = new Decompressor(1024, 16);  // 1 KiB ceiling
        $zip = $this->buildZip(['bomb.xml' => str_repeat('A', 5 * 1024 * 1024)]);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/oversized/i');
        $d->decompress($zip);
    }

    /** @param array<string, string> $entries filename => content */
    private function buildZip(array $entries): string
    {
        $tmp = tempnam(sys_get_temp_dir(), 'dmarc_test_');
        self::assertNotFalse($tmp);

        $zip = new \ZipArchive();
        $zip->open($tmp, \ZipArchive::OVERWRITE);
        foreach ($entries as $name => $content) {
            $zip->addFromString($name, $content);
        }
        $zip->close();

        $bytes = (string) file_get_contents($tmp);
        unlink($tmp);

        return $bytes;
    }
}
