<?php

declare(strict_types=1);

namespace App\Ingest;

use DateTimeImmutable;
use DateTimeZone;
use JsonException;
use RuntimeException;

/**
 * Spec §12 (RFC 8460 TLS-RPT JSON reports), mirroring ReportParser's
 * tolerance philosophy (§5): individual malformed policies/failure-details
 * are logged and skipped rather than failing the whole report. Unlike
 * DMARC's `report_metadata/date_range` (Unix timestamps), RFC 8460's
 * `date-range` is ISO 8601 strings.
 */
final class TlsRptParser
{
    private const VALID_POLICY_TYPES = ['tlsa', 'sts', 'no-policy-found'];

    /** @var list<string> */
    private array $warnings = [];

    public function parse(string $json): ParsedTlsRptReport
    {
        $this->warnings = [];

        try {
            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('Malformed JSON: ' . $e->getMessage());
        }

        if (!is_array($data)) {
            throw new RuntimeException('Report is not a JSON object');
        }

        $orgName     = $this->str($data, 'organization-name');
        $reportId    = $this->str($data, 'report-id');
        $dateRange   = $data['date-range'] ?? null;
        $policiesRaw = $data['policies']   ?? null;

        if ($orgName === null || $reportId === null || !is_array($dateRange) || !is_array($policiesRaw)) {
            throw new RuntimeException('Missing organization-name, report-id, date-range, or policies');
        }

        $dateBegin = $this->timestamp($dateRange, 'start-datetime');
        $dateEnd   = $this->timestamp($dateRange, 'end-datetime');

        $policies = [];
        foreach ($policiesRaw as $i => $policyRaw) {
            if (!is_array($policyRaw)) {
                $this->warnings[] = sprintf('policies[%d]: not an object', (int) $i);

                continue;
            }

            try {
                $policies[] = $this->extractPolicy($policyRaw);
            } catch (RuntimeException $e) {
                $this->warnings[] = sprintf('policies[%d]: %s', (int) $i, $e->getMessage());
            }
        }

        return new ParsedTlsRptReport(
            organizationName: strtolower($orgName),
            reportId: $reportId,
            dateBegin: $dateBegin,
            dateEnd: $dateEnd,
            policies: $policies,
            warnings: $this->warnings,
        );
    }

    /**
     * @param array<array-key, mixed> $policyRaw
     *
     * @return array<string, mixed>
     */
    private function extractPolicy(array $policyRaw): array
    {
        $policy = $policyRaw['policy'] ?? null;
        if (!is_array($policy)) {
            throw new RuntimeException('missing policy object');
        }

        $domain = $this->str($policy, 'policy-domain');
        if ($domain === null) {
            throw new RuntimeException('missing policy-domain');
        }

        $policyType = $this->str($policy, 'policy-type');
        if ($policyType === null || !in_array($policyType, self::VALID_POLICY_TYPES, true)) {
            throw new RuntimeException('invalid or missing policy-type');
        }

        $summary = $policyRaw['summary'] ?? [];
        $summary = is_array($summary) ? $summary : [];

        $failureDetailsRaw = $policyRaw['failure-details'] ?? [];
        $failureDetailsRaw = is_array($failureDetailsRaw) ? $failureDetailsRaw : [];

        $failureDetails = [];
        foreach ($failureDetailsRaw as $j => $detailRaw) {
            if (!is_array($detailRaw)) {
                $this->warnings[] = sprintf('failure-details[%d]: not an object', (int) $j);

                continue;
            }

            try {
                $failureDetails[] = $this->extractFailureDetail($detailRaw);
            } catch (RuntimeException $e) {
                $this->warnings[] = sprintf('failure-details[%d]: %s', (int) $j, $e->getMessage());
            }
        }

        return [
            'domain'          => strtolower($domain),
            'policy_type'     => $policyType,
            'policy_string'   => $this->joinedStrings($policy['policy-string'] ?? null),
            'mx_host'         => $this->joinedStrings($policy['mx-host'] ?? null),
            'success_count'   => max(0, (int) ($summary['total-successful-session-count'] ?? 0)),
            'failure_count'   => max(0, (int) ($summary['total-failure-session-count'] ?? 0)),
            'failure_details' => $failureDetails,
        ];
    }

    /**
     * @param array<array-key, mixed> $detailRaw
     *
     * @return array<string, mixed>
     */
    private function extractFailureDetail(array $detailRaw): array
    {
        $resultType = $this->str($detailRaw, 'result-type');
        if ($resultType === null) {
            throw new RuntimeException('missing result-type');
        }

        // sending-mta-ip/receiving-ip are optional per RFC 8460 — unlike
        // DMARC's source_ip (invalid skips the whole record), a missing or
        // unparseable IP here just becomes null; the entry itself is kept.
        return [
            'result_type'            => $resultType,
            'sending_mta_ip'         => $this->validIp($detailRaw['sending-mta-ip'] ?? null),
            'receiving_mx_hostname'  => $this->lower($this->str($detailRaw, 'receiving-mx-hostname')),
            'receiving_mx_helo'      => $this->lower($this->str($detailRaw, 'receiving-mx-helo')),
            'receiving_ip'           => $this->validIp($detailRaw['receiving-ip'] ?? null),
            'failed_session_count'   => max(0, (int) ($detailRaw['failed-session-count'] ?? 0)),
            'additional_information' => $this->str($detailRaw, 'additional-information'),
            'failure_reason_code'    => $this->str($detailRaw, 'failure-reason-code'),
        ];
    }

    private function validIp(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }

        return filter_var($value, FILTER_VALIDATE_IP) !== false ? $value : null;
    }

    private function lower(?string $value): ?string
    {
        return $value === null ? null : strtolower($value);
    }

    private function joinedStrings(mixed $value): ?string
    {
        if (!is_array($value) || $value === []) {
            return null;
        }

        $lines = [];

        foreach ($value as $line) {
            if (is_string($line) && trim($line) !== '') {
                $lines[] = trim($line);
            }
        }

        return $lines === [] ? null : implode("\n", $lines);
    }

    /** @param array<array-key, mixed> $data */
    private function str(array $data, string $key): ?string
    {
        $value = $data[$key] ?? null;

        if (!is_string($value)) {
            return null;
        }

        $value = trim($value);

        return $value === '' ? null : $value;
    }

    /** @param array<array-key, mixed> $range */
    private function timestamp(array $range, string $key): DateTimeImmutable
    {
        $value = $this->str($range, $key);

        if ($value === null) {
            throw new RuntimeException("missing $key");
        }

        try {
            return (new DateTimeImmutable($value))->setTimezone(new DateTimeZone('UTC'));
        } catch (\Exception $e) {
            throw new RuntimeException("invalid $key: " . $e->getMessage());
        }
    }
}
