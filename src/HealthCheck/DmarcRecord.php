<?php

declare(strict_types=1);

namespace App\HealthCheck;

/**
 * A parsed `_dmarc` TXT record. Shared by DmarcCheck and
 * ReportDestinationAuthCheck (the latter only needs the rua domains) so
 * the tag=value parsing logic exists once.
 */
final readonly class DmarcRecord
{
    /**
     * @param list<string> $ruaAddresses
     * @param list<string> $rufAddresses
     */
    private function __construct(
        public ?string $policy,
        public ?string $subdomainPolicy,
        public array $ruaAddresses,
        public array $rufAddresses,
        public ?int $pct,
        public ?string $adkim,
        public ?string $aspf,
        // DMARCbis (RFC 9989) additions. 'pct' above is kept even though
        // RFC 9989 removed it as a defined tag — a currently-published
        // record may still have it, and later deprecation-flagging
        // (docs/feature-dmarcbis.md Phase 3) needs to see that.
        public ?string $nonExistentSubdomainPolicy = null,
        public ?string $psd = null,
        public ?string $testing = null,
    ) {
    }

    public static function parse(string $raw): ?self
    {
        $tags = [];

        foreach (explode(';', $raw) as $part) {
            $part = trim($part);

            if ($part === '' || !str_contains($part, '=')) {
                continue;
            }

            [$key, $value]                = explode('=', $part, 2);
            $tags[strtolower(trim($key))] = trim($value);
        }

        if (strtoupper($tags['v'] ?? '') !== 'DMARC1') {
            return null;
        }

        return new self(
            isset($tags['p']) ? strtolower($tags['p']) : null,
            isset($tags['sp']) ? strtolower($tags['sp']) : null,
            self::mailtoAddresses($tags['rua'] ?? ''),
            self::mailtoAddresses($tags['ruf'] ?? ''),
            isset($tags['pct']) && ctype_digit($tags['pct']) ? (int) $tags['pct'] : null,
            $tags['adkim'] ?? null,
            $tags['aspf']  ?? null,
            isset($tags['np']) ? strtolower($tags['np']) : null,
            isset($tags['psd']) ? strtolower($tags['psd']) : null,
            isset($tags['t']) ? strtolower($tags['t']) : null,
        );
    }

    /** @return list<string> lowercased destination domains, deduplicated */
    public function ruaDomains(): array
    {
        $domains = [];

        foreach ($this->ruaAddresses as $address) {
            $at = strrpos($address, '@');

            if ($at !== false) {
                $domains[] = strtolower(substr($address, $at + 1));
            }
        }

        return array_values(array_unique($domains));
    }

    /** Same tag order/format ReportParser::formatPolicy() writes from report data, so both writers agree. */
    public function toPolicyString(): string
    {
        $parts = [];

        foreach ([
            'p'     => $this->policy,
            'sp'    => $this->subdomainPolicy,
            'np'    => $this->nonExistentSubdomainPolicy,
            'pct'   => $this->pct,
            'adkim' => $this->adkim,
            'aspf'  => $this->aspf,
            't'     => $this->testing,
        ] as $tag => $value) {
            if ($value !== null && $value !== '') {
                $parts[] = "$tag=$value";
            }
        }

        return implode('; ', $parts);
    }

    /** @return list<string> */
    private static function mailtoAddresses(string $value): array
    {
        if ($value === '') {
            return [];
        }

        $addresses = [];

        foreach (explode(',', $value) as $uri) {
            $uri = trim($uri);
            // Strip an optional "!<size>" suffix (RFC 7489 report-size limit).
            $uri = preg_replace('/![0-9]+[kmgt]?$/i', '', $uri) ?? $uri;

            if (str_starts_with(strtolower($uri), 'mailto:')) {
                $addresses[] = substr($uri, 7);
            }
        }

        return $addresses;
    }
}
