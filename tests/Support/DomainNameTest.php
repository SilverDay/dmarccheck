<?php

declare(strict_types=1);

namespace App\Tests\Support;

use App\Support\DomainName;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DomainNameTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function validDomains(): iterable
    {
        yield 'simple domain' => ['example.com'];
        yield 'subdomain' => ['mail.example.com'];
        yield 'multi-level tld' => ['example.co.uk'];
        yield 'digits and hyphens mid-label' => ['my-mail-01.example.com'];
        yield 'punycode label' => ['xn--exmple-cua.com'];
        yield 'uppercase' => ['EXAMPLE.COM'];
        yield 'single-char labels' => ['a.b.co'];
    }

    #[DataProvider('validDomains')]
    public function testAcceptsValidDomains(string $domain): void
    {
        self::assertTrue(DomainName::isValid($domain));
    }

    /** @return iterable<string, array{string}> */
    public static function invalidDomains(): iterable
    {
        yield 'empty string' => [''];
        yield 'no dot / bare label' => ['example'];
        yield 'leading hyphen in label' => ['-example.com'];
        yield 'trailing hyphen in label' => ['example-.com'];
        yield 'empty label from double dot' => ['example..com'];
        yield 'leading dot' => ['.example.com'];
        yield 'trailing dot' => ['example.com.'];
        yield 'contains a path' => ['example.com/path'];
        yield 'contains whitespace' => ['exa mple.com'];
        yield 'contains a space at the edge' => [' example.com'];
        yield 'label over 63 chars' => [str_repeat('a', 64) . '.com'];
        yield 'total over 255 chars' => [implode('.', array_fill(0, 30, str_repeat('a', 8))) . '.com'];
        yield 'underscore not allowed' => ['exa_mple.com'];
    }

    #[DataProvider('invalidDomains')]
    public function testRejectsInvalidDomains(string $domain): void
    {
        self::assertFalse(DomainName::isValid($domain));
    }
}
