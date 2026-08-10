<?php

declare(strict_types=1);

namespace App\HealthCheck;

/**
 * RFC 9989 §4.10 DNS Tree Walk / §4.10.2 Organizational Domain selection
 * (DMARCbis's replacement for Public Suffix List based org-domain
 * discovery — this tool never uses a PSL). Only used as `DmarcCheck`'s
 * fallback when a domain has no `_dmarc` record of its own, to distinguish
 * "genuinely uncovered" from "covered by inheritance from an ancestor" —
 * see docs/feature-dmarcbis.md Phase 2.
 *
 * A valid record without a `psd` tag does NOT stop the walk (RFC 9989
 * §4.10 step 6: only `psd=n`/`psd=y` stops it) — it's remembered as a
 * candidate and the walk continues until a psd-tagged record appears or
 * labels run out. §4.10.2 then picks the fewest-labels candidate, which in
 * the near-universal case of a single record found anywhere in the chain
 * is just that one record — psd= has ~zero real-world adoption yet.
 */
final class OrgDomain
{
    /** RFC 9989 §5.1.8 anti-abuse cap — total DNS queries per walk. */
    private const int MAX_QUERIES = 8;

    /** RFC 9989 §4.10 step 4 — domains with >= this many labels jump straight to this many remaining, instead of stripping one at a time. */
    private const int LABEL_STRIP_THRESHOLD = 8;

    public function __construct(private readonly DnsResolver $dns)
    {
    }

    public function resolve(string $domain): OrgDomainResult
    {
        $domain  = strtolower($domain);
        $target  = $domain;
        $queried = [];

        /** @var list<array{0: string, 1: DmarcRecord}> $candidates */
        $candidates  = [];
        $queriesLeft = self::MAX_QUERIES;

        while ($queriesLeft > 0) {
            $queried[] = $target;
            $txt       = $this->dns->txt('_dmarc.' . $target);
            $queriesLeft--;

            $valid = array_values(array_filter(
                $txt,
                static fn (string $t): bool => str_starts_with(strtolower(trim($t)), 'v=dmarc1')
            ));

            // RFC 9989 §4.10 step 2/6: multiple records at one target are
            // discarded entirely, not an error — the walk simply continues
            // past that target. Different from DmarcCheck's own top-level
            // handling, which deliberately treats multiple records as FAIL.
            if (\count($valid) === 1) {
                $record = DmarcRecord::parse($valid[0]);

                if ($record !== null) {
                    if ($record->psd === 'n') {
                        return new OrgDomainResult($target, $record, 'treewalk', $queried);
                    }

                    if ($record->psd === 'y' && $target !== $domain) {
                        return new OrgDomainResult($this->oneLabelBelow($domain, $target), $record, 'treewalk', $queried);
                    }

                    $candidates[] = [$target, $record];
                }
            }

            $labels = explode('.', $target);
            $x      = \count($labels);

            if ($x <= 1) {
                break;
            }

            $target = $x < self::LABEL_STRIP_THRESHOLD
                ? implode('.', \array_slice($labels, 1))
                : implode('.', \array_slice($labels, -7));
        }

        if ($candidates === []) {
            return new OrgDomainResult(null, null, 'treewalk', $queried);
        }

        usort(
            $candidates,
            static fn (array $a, array $b): int => \count(explode('.', $a[0])) <=> \count(explode('.', $b[0]))
        );

        [$orgDomain, $record] = $candidates[0];

        return new OrgDomainResult($orgDomain, $record, 'treewalk', $queried);
    }

    /**
     * The name one label below $psdTarget, taken from $domain's own label
     * chain (not an arbitrary label) — $psdTarget is always a label-suffix
     * of $domain, since the walk only ever strips labels off $domain.
     */
    private function oneLabelBelow(string $domain, string $psdTarget): string
    {
        $domainLabels = explode('.', $domain);
        $targetLabels = \count(explode('.', $psdTarget));

        return implode('.', \array_slice($domainLabels, -($targetLabels + 1)));
    }
}
