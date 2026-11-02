<?php

declare(strict_types=1);

namespace App\Recommendation;

use App\Support\Ip;
use DateTimeImmutable;
use PDO;

final class ReportAuthEvidenceRepository
{
    private const int MAX_SOURCE_IPS = 50;
    private const int MAX_QUERY_DAYS = 366;
    private const int MAX_ROWS       = 2000;

    public function __construct(private readonly PDO $pdo)
    {
    }

    /**
     * Finds the raw SPF identities and DKIM signatures behind currently firing
     * R1/R2 recommendations. Results are limited to each finding's analysis
     * window and to recent report records.
     *
     * @param list<RecommendationRow> $recommendations
     *
     * @return array{findings: array<int, array{spf_domains: list<string>, dkim_signatures: list<array{domain: string, selector: string}>}>, truncated: bool}
     */
    public function forRecommendations(int $domainId, array $recommendations): array
    {
        $byBinaryIp = [];
        $truncated  = false;

        foreach ($recommendations as $recommendation) {
            if (!\in_array($recommendation->ruleId, ['R1', 'R2'], true)
                || $recommendation->subject === null
                || !Ip::isValidIpOrCidr($recommendation->subject)
                || str_contains($recommendation->subject, '/')) {
                continue;
            }

            $binaryIp = Ip::toBinary($recommendation->subject);
            $key      = bin2hex($binaryIp);
            $days     = $recommendation->evidence['window_days'] ?? 30;

            if (!\is_int($days)) {
                $days = 30;
            } elseif ($days > self::MAX_QUERY_DAYS) {
                $truncated = true;
                $days      = self::MAX_QUERY_DAYS;
            } else {
                $days = max(1, $days);
            }

            $byBinaryIp[$key] ??= [
                'binary'   => $binaryIp,
                'findings' => [],
            ];
            $byBinaryIp[$key]['findings'][$recommendation->id] = [
                'rule' => $recommendation->ruleId,
                'days' => $days,
            ];
        }

        if ($byBinaryIp === []) {
            return ['findings' => [], 'truncated' => $truncated];
        }

        $truncated  = $truncated || \count($byBinaryIp) > self::MAX_SOURCE_IPS;
        $byBinaryIp = array_slice($byBinaryIp, 0, self::MAX_SOURCE_IPS, true);
        $maxDays    = max(array_map(
            static fn (array $source): int => max(array_column($source['findings'], 'days')),
            $byBinaryIp
        ));
        $findings = [];

        foreach ($byBinaryIp as $source) {
            foreach ($source['findings'] as $recommendationId => $finding) {
                $findings[$recommendationId] = ['spf_domains' => [], 'dkim_signatures' => []];
            }
        }

        $placeholders = implode(',', array_fill(0, \count($byBinaryIp), '?'));
        $stmt         = $this->pdo->prepare(
            "SELECT rr.source_ip, rr.dkim_result, rr.spf_result, r.date_begin,
                    ar.type, ar.domain, ar.selector
               FROM report_records rr
               JOIN reports r ON r.id = rr.report_id
               LEFT JOIN auth_results ar ON ar.record_id = rr.id AND ar.type IN ('spf', 'dkim')
              WHERE r.domain_id = ?
                AND rr.source_ip IN ($placeholders)
                AND r.date_begin >= NOW() - INTERVAL $maxDays DAY
                AND ((rr.dkim_result = 'pass' AND rr.spf_result = 'fail')
                  OR (rr.dkim_result = 'fail' AND rr.spf_result = 'pass'))
              ORDER BY r.date_begin DESC, rr.id DESC
              LIMIT " . (self::MAX_ROWS + 1)
        );
        $stmt->execute([$domainId, ...array_column($byBinaryIp, 'binary')]);
        $rows      = $stmt->fetchAll();
        $truncated = $truncated || \count($rows) > self::MAX_ROWS;

        foreach (array_slice($rows, 0, self::MAX_ROWS) as $row) {
            $ipKey  = bin2hex((string) $row['source_ip']);
            $source = $byBinaryIp[$ipKey] ?? null;

            if ($source === null) {
                continue;
            }

            $spfFailOnly  = $row['dkim_result'] === 'pass' && $row['spf_result'] === 'fail';
            $dkimFailOnly = $row['dkim_result'] === 'fail' && $row['spf_result'] === 'pass';

            foreach ($source['findings'] as $recommendationId => $finding) {
                $cutoff = (new DateTimeImmutable('now'))->modify('-' . $finding['days'] . ' days');

                if (new DateTimeImmutable((string) $row['date_begin']) < $cutoff) {
                    continue;
                }

                if ($finding['rule'] === 'R1' && $spfFailOnly && $row['type'] === 'spf'
                                              && \is_string($row['domain']) && $row['domain'] !== '') {
                    $findings[$recommendationId]['spf_domains'][$row['domain']] = true;
                }

                if ($finding['rule'] === 'R2' && $dkimFailOnly && $row['type'] === 'dkim'
                                              && \is_string($row['domain']) && $row['domain']     !== ''
                                              && \is_string($row['selector']) && $row['selector'] !== '') {
                    $findings[$recommendationId]['dkim_signatures'][$row['domain'] . "\0" . $row['selector']] = [
                        'domain'   => $row['domain'],
                        'selector' => $row['selector'],
                    ];
                }
            }
        }

        foreach ($findings as &$finding) {
            $finding['spf_domains'] = array_keys($finding['spf_domains']);
            sort($finding['spf_domains']);
            $finding['dkim_signatures'] = array_values($finding['dkim_signatures']);
            usort(
                $finding['dkim_signatures'],
                static fn (array $a, array $b): int => [$a['domain'], $a['selector']] <=> [$b['domain'], $b['selector']]
            );
        }

        unset($finding);

        return ['findings' => $findings, 'truncated' => $truncated];
    }
}
