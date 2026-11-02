<?php

declare(strict_types=1);

namespace App\Reports;

use DateTimeImmutable;
use InvalidArgumentException;

final readonly class ReportSearchCriteria
{
    public const int MAX_CUSTOM_RANGE_DAYS = 366;

    /**
     * @param string|null                      $label
     * @param 'pass'|'fail'|null               $dkimResult
     * @param 'pass'|'fail'|null               $spfResult
     * @param 'none'|'quarantine'|'reject'|null $disposition
     */
    public function __construct(
        public ?int $domainId,
        public string $fromDate,
        public string $throughDate,
        public ?string $label = null,
        public ?string $dkimResult = null,
        public ?string $spfResult = null,
        public ?string $disposition = null,
        public ?string $asnOrg = null,
    ) {
    }

    /**
     * @param array<string, mixed> $query
     */
    public static function fromQuery(array $query, ?DateTimeImmutable $today = null): self
    {
        $today = ($today ?? new DateTimeImmutable('today'))->setTime(0, 0);

        $domainValue = self::stringValue($query, 'domain');
        $domainId    = null;

        if ($domainValue !== null && $domainValue !== '' && $domainValue !== 'all') {
            if (!ctype_digit($domainValue) || (int) $domainValue < 1) {
                throw new InvalidArgumentException('Choose a valid domain.');
            }

            $domainId = (int) $domainValue;
        }

        $range = self::stringValue($query, 'range') ?? '30';

        if ($range === 'custom') {
            $fromDate    = self::dateValue(self::stringValue($query, 'from'), 'Start date');
            $throughDate = self::dateValue(self::stringValue($query, 'to'), 'End date');
        } elseif (\in_array($range, ['7', '30', '90'], true)) {
            $throughDate = $today->format('Y-m-d');
            $fromDate    = $today->modify('-' . ((int) $range - 1) . ' days')->format('Y-m-d');
        } else {
            throw new InvalidArgumentException('Choose 7, 30, or 90 days, or a custom date range.');
        }

        if ($fromDate > $throughDate) {
            throw new InvalidArgumentException('Start date must be on or before end date.');
        }

        $from = new DateTimeImmutable($fromDate);
        $to   = new DateTimeImmutable($throughDate);

        if ((int) $from->diff($to)->format('%a') >= self::MAX_CUSTOM_RANGE_DAYS) {
            throw new InvalidArgumentException('Date range cannot exceed 366 days.');
        }

        $label = self::stringValue($query, 'label');

        if ($label !== null) {
            $label = trim($label);

            if (mb_strlen($label) > 64) {
                throw new InvalidArgumentException('Sender label filter must be 64 characters or fewer.');
            }

            if ($label === '') {
                $label = null;
            }
        }

        $dkimResult  = self::enumValue($query, 'dkim', ['pass', 'fail']);
        $spfResult   = self::enumValue($query, 'spf', ['pass', 'fail']);
        $disposition = self::enumValue($query, 'disposition', ['none', 'quarantine', 'reject']);
        $asnOrg      = self::stringValue($query, 'asn_org');

        if ($asnOrg !== null) {
            $asnOrg = trim($asnOrg);

            if (mb_strlen($asnOrg) > 100) {
                throw new InvalidArgumentException('ASN/organization filter must be 100 characters or fewer.');
            }

            if ($asnOrg === '') {
                $asnOrg = null;
            }
        }

        return new self($domainId, $fromDate, $throughDate, $label, $dkimResult, $spfResult, $disposition, $asnOrg);
    }

    /**
     * @param array<string, mixed> $query
     */
    private static function stringValue(array $query, string $key): ?string
    {
        if (!array_key_exists($key, $query)) {
            return null;
        }

        if (!\is_string($query[$key])) {
            throw new InvalidArgumentException("The $key filter must be a single text value.");
        }

        return $query[$key];
    }

    /**
     * @param array<string, mixed> $query
     * @param list<string>         $allowed
     */
    private static function enumValue(array $query, string $key, array $allowed): ?string
    {
        $value = self::stringValue($query, $key);

        if ($value === null || $value === '') {
            return null;
        }

        if (!\in_array($value, $allowed, true)) {
            throw new InvalidArgumentException("Invalid $key filter.");
        }

        return $value;
    }

    private static function dateValue(?string $value, string $label): string
    {
        if ($value === null || !preg_match('/^\d{4}-\d{2}-\d{2}$/D', $value)) {
            throw new InvalidArgumentException("$label must use YYYY-MM-DD.");
        }

        $date   = DateTimeImmutable::createFromFormat('!Y-m-d', $value);
        $errors = DateTimeImmutable::getLastErrors();

        if ($date === false || ($errors !== false && ($errors['warning_count'] > 0 || $errors['error_count'] > 0)) || $date->format('Y-m-d') !== $value) {
            throw new InvalidArgumentException("$label is not a valid calendar date.");
        }

        return $value;
    }
}
