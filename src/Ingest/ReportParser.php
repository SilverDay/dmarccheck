<?php

declare(strict_types=1);

namespace App\Ingest;

use DOMDocument;
use RuntimeException;

/**
 * Spec §5 (parsing) + §4.1 (XXE hardening).
 *
 * XXE posture on the target stack (PHP 8.3+, libxml >= 2.9):
 *   - External-entity substitution is OFF by default.
 *   - libxml_disable_entity_loader() is DEPRECATED — do not call it.
 *   - The rule is therefore negative: never pass LIBXML_NOENT or
 *     LIBXML_DTDLOAD, since those re-enable the risk.
 *   - On PHP 8.4 / libxml >= 2.13, LIBXML_NO_XXE is passed as
 *     defense-in-depth (feature-detected, so this stays 8.3-compatible).
 *
 * Parsing is deliberately tolerant per §5: vendors deviate from the RFC 7489
 * schema constantly. Individual malformed <record> blocks are skipped and
 * counted rather than failing the whole report.
 */
final class ReportParser
{
    /** @var list<string> */
    private array $recordWarnings = [];

    public function parse(string $xml): ParsedReport
    {
        $flags = LIBXML_NONET | LIBXML_COMPACT;

        // Feature-detect so this stays correct on both 8.3 and 8.4+.
        if (defined('LIBXML_NO_XXE')) {
            $flags |= \LIBXML_NO_XXE;
        }

        $previous = libxml_use_internal_errors(true);

        try {
            $doc = new DOMDocument();
            // NB: no LIBXML_NOENT, no LIBXML_DTDLOAD — see class docblock.
            $loaded = $doc->loadXML($xml, $flags);

            if ($loaded === false) {
                throw new RuntimeException('Malformed XML: ' . $this->firstLibxmlError());
            }

            // Belt and braces: a DTD has no legitimate place in a DMARC report.
            if ($doc->doctype !== null) {
                throw new RuntimeException('Report declares a DOCTYPE; rejected');
            }

            return $this->extract($doc);
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
    }

    private function firstLibxmlError(): string
    {
        $errors = libxml_get_errors();

        return $errors === [] ? 'unknown error' : trim($errors[0]->message);
    }

    private function extract(DOMDocument $doc): ParsedReport
    {
        $this->recordWarnings = [];

        $root = $doc->documentElement;
        if ($root === null) {
            throw new RuntimeException('Empty document');
        }

        $meta   = $this->firstChild($root, 'report_metadata');
        $policy = $this->firstChild($root, 'policy_published');

        if ($meta === null || $policy === null) {
            throw new RuntimeException('Missing report_metadata or policy_published');
        }

        $range = $this->firstChild($meta, 'date_range');

        // §5: match on policy_published/domain — report_metadata does not
        // reliably state which of our domains the report concerns.
        $domain = $this->text($policy, 'domain');
        if ($domain === '') {
            throw new RuntimeException('policy_published/domain is empty');
        }

        $records = [];
        foreach ($root->getElementsByTagName('record') as $i => $recordNode) {
            try {
                $records[] = $this->extractRecord($recordNode);
            } catch (RuntimeException $e) {
                // Log-and-skip, per §5 — one bad record must not sink the batch.
                $this->recordWarnings[] = sprintf('record[%d]: %s', $i, $e->getMessage());
            }
        }

        return new ParsedReport(
            domain: strtolower($domain),
            reporterOrg: strtolower($this->text($meta, 'org_name')),
            reportId: $this->text($meta, 'report_id'),
            dateBegin: $this->timestamp($range, 'begin'),
            dateEnd: $this->timestamp($range, 'end'),
            policyPublished: $this->formatPolicy($policy),
            records: $records,
            warnings: $this->recordWarnings,
            generator: $this->text($meta, 'generator') ?: null,
            discoveryMethod: $this->text($policy, 'discovery_method') ?: null,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function extractRecord(\DOMNode $node): array
    {
        $row = $this->firstChild($node, 'row');
        if ($row === null) {
            throw new RuntimeException('missing <row>');
        }

        $sourceIp = $this->text($row, 'source_ip');
        if (filter_var($sourceIp, FILTER_VALIDATE_IP) === false) {
            throw new RuntimeException('invalid source_ip');
        }

        $evaluated   = $this->firstChild($row, 'policy_evaluated');
        $identifiers = $this->firstChild($node, 'identifiers');
        $authResults = $this->firstChild($node, 'auth_results');

        return [
            'source_ip'   => $sourceIp,
            'count'       => max(0, (int) $this->text($row, 'count')),
            'disposition' => $this->enum($this->text($evaluated, 'disposition'), ['none', 'quarantine', 'reject'], 'none'),
            'dkim_result' => $this->enum($this->text($evaluated, 'dkim'), ['pass', 'fail'], 'fail'),
            'spf_result'  => $this->enum($this->text($evaluated, 'spf'), ['pass', 'fail'], 'fail'),
            'header_from' => strtolower($this->text($identifiers, 'header_from')),
            // DMARCbis (RFC 9990) additions — absent on every classic-era report.
            'envelope_from' => strtolower($this->text($identifiers, 'envelope_from')) ?: null,
            'envelope_to'   => strtolower($this->text($identifiers, 'envelope_to')) ?: null,
            'auth_results'  => $this->extractAuthResults($authResults),
        ];
    }

    /**
     * @return list<array<string, string|null>>
     */
    private function extractAuthResults(?\DOMNode $node): array
    {
        if ($node === null) {
            return [];
        }

        $out = [];
        foreach (['dkim', 'spf'] as $type) {
            foreach ($node->childNodes as $child) {
                if (!$child instanceof \DOMElement || $child->nodeName !== $type) {
                    continue;
                }

                $out[] = [
                    'type'     => $type,
                    'domain'   => strtolower($this->text($child, 'domain')) ?: null,
                    'selector' => $type === 'dkim' ? ($this->text($child, 'selector') ?: null) : null,
                    'result'   => $this->text($child, 'result') ?: null,
                ];
            }
        }

        return $out;
    }

    private function formatPolicy(\DOMNode $policy): string
    {
        $parts = [];
        // 'pct' is kept even though RFC 9989 removed it as a defined tag —
        // a report can still describe a classic-era published record, and
        // downstream deprecation-flagging (docs/feature-dmarcbis.md Phase 3)
        // needs to see it. 'np' (non-existent-subdomain policy) is new.
        foreach (['p', 'sp', 'np', 'pct', 'adkim', 'aspf'] as $tag) {
            $value = $this->text($policy, $tag);
            if ($value !== '') {
                $parts[] = "$tag=$value";
            }
        }

        // 't' (test mode, RFC 9989) — the schema element name wasn't
        // confirmed with certainty (RFC 9990 Appendix C references it as
        // "testing"), so both are read defensively; same tolerant stance
        // every other tag here already takes toward vendor deviation.
        $testing = $this->text($policy, 't') ?: $this->text($policy, 'testing');
        if ($testing !== '') {
            $parts[] = "t=$testing";
        }

        return implode('; ', $parts);
    }

    /** @param list<string> $allowed */
    private function enum(string $value, array $allowed, string $fallback): string
    {
        $value = strtolower(trim($value));

        return in_array($value, $allowed, true) ? $value : $fallback;
    }

    private function firstChild(?\DOMNode $parent, string $name): ?\DOMElement
    {
        if ($parent === null) {
            return null;
        }

        foreach ($parent->childNodes as $child) {
            if ($child instanceof \DOMElement && $child->nodeName === $name) {
                return $child;
            }
        }

        return null;
    }

    private function text(?\DOMNode $parent, string $name): string
    {
        $node = $this->firstChild($parent, $name);

        return $node === null ? '' : trim($node->textContent);
    }

    private function timestamp(?\DOMNode $parent, string $name): \DateTimeImmutable
    {
        $raw = (int) $this->text($parent, $name);

        // Report date ranges are UTC Unix timestamps — normalise here so all
        // downstream aggregation is consistent.
        return (new \DateTimeImmutable('@' . $raw))->setTimezone(new \DateTimeZone('UTC'));
    }
}
