<?php

declare(strict_types=1);

namespace App\Recommendation;

use App\Enrichment\KnownSenderMatcher;
use App\HealthCheck\Checks\SpfCheck;
use App\HealthCheck\DnsResolver;
use App\Support\Ip;
use PDO;
use RuntimeException;

/**
 * The DB- and network-touching piece of the recommendation engine (spec
 * §10.2): aggregates report_records/auth_results into per-IP SourceStats
 * for two windows, and runs a live SPF lookup-count check (§10.2: "computed
 * at analysis time," not read from a possibly-stale health-check row) by
 * reusing App\HealthCheck\Checks\SpfCheck rather than re-implementing SPF
 * DNS-lookup counting. Not unit-tested by design, consistent with
 * ReportStore/IpEnrichmentRepository elsewhere in this codebase — the
 * Rule classes it feeds are the tested layer.
 */
final class AnalysisContextBuilder
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly DnsResolver $dns,
        private readonly int $windowDays,
        private readonly int $sustainedWindowDays,
        private readonly int $sustainedMinDays,
    ) {
    }

    public function build(int $domainId, string $domain): AnalysisContext
    {
        $domainRow = $this->fetchDomain($domainId);
        $matcher   = KnownSenderMatcher::fromDatabase($this->pdo);

        return new AnalysisContext(
            $domainId,
            $domain,
            $domainRow['current_published_policy'] !== null ? (string) $domainRow['current_published_policy'] : null,
            $domainRow['approved_baseline_policy'] !== null ? (string) $domainRow['approved_baseline_policy'] : null,
            (string) $domainRow['target_policy'],
            (bool) $domainRow['non_sending'],
            $this->buildStats($domainId, $this->windowDays, $matcher),
            $this->buildStats($domainId, $this->sustainedWindowDays, $matcher),
            $this->liveSpfLookupCount($domain),
            $this->windowDays,
            $this->sustainedMinDays,
        );
    }

    /** @return array{current_published_policy: ?string, approved_baseline_policy: ?string, target_policy: string, non_sending: int} */
    private function fetchDomain(int $domainId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT current_published_policy, approved_baseline_policy, target_policy, non_sending
               FROM domains WHERE id = ?'
        );
        $stmt->execute([$domainId]);
        $row = $stmt->fetch();

        if ($row === false) {
            throw new RuntimeException("Domain $domainId not found");
        }

        return $row;
    }

    /** @return list<SourceStat> */
    private function buildStats(int $domainId, int $windowDays, KnownSenderMatcher $matcher): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT rr.id, rr.source_ip, rr.`count`, rr.dkim_result, rr.spf_result, rr.header_from, r.date_begin
               FROM report_records rr
               JOIN reports r ON r.id = rr.report_id
              WHERE r.domain_id = ? AND r.date_begin >= NOW() - INTERVAL ? DAY'
        );
        $stmt->bindValue(1, $domainId, PDO::PARAM_INT);
        $stmt->bindValue(2, $windowDays, PDO::PARAM_INT);
        $stmt->execute();
        $records = $stmt->fetchAll();

        if ($records === []) {
            return [];
        }

        $recordIds = array_map(static fn (array $r): int => (int) $r['id'], $records);
        $rawAuth   = $this->fetchRawAuthResults($recordIds);

        /** @var array<string, array{count: int, pass: int, both_failed: int, spf_only_fail: int, dkim_only_fail: int, spf_alignment_issue: bool, dkim_alignment_issue: bool, header_from: array<string, true>, days: array<string, true>}> $byIp */
        $byIp = [];

        foreach ($records as $row) {
            $ip         = Ip::toString((string) $row['source_ip']);
            $count      = (int) $row['count'];
            $dkimResult = (string) $row['dkim_result'];
            $spfResult  = (string) $row['spf_result'];
            $headerFrom = (string) ($row['header_from'] ?? '');
            $day        = substr((string) $row['date_begin'], 0, 10);
            $raw        = $rawAuth[(int) $row['id']] ?? ['spf_pass' => false, 'dkim_pass' => false];

            $byIp[$ip] ??= [
                'count'               => 0, 'pass' => 0, 'both_failed' => 0, 'spf_only_fail' => 0, 'dkim_only_fail' => 0,
                'spf_alignment_issue' => false, 'dkim_alignment_issue' => false, 'header_from' => [], 'days' => [],
            ];

            $byIp[$ip]['count'] += $count;

            if ($dkimResult === 'pass' || $spfResult === 'pass') {
                $byIp[$ip]['pass'] += $count;
            }

            if ($dkimResult === 'fail' && $spfResult === 'fail') {
                $byIp[$ip]['both_failed'] += $count;
            } elseif ($dkimResult === 'pass' && $spfResult === 'fail') {
                $byIp[$ip]['spf_only_fail'] += $count;
            } elseif ($dkimResult === 'fail' && $spfResult === 'pass') {
                $byIp[$ip]['dkim_only_fail'] += $count;
            }

            if ($spfResult === 'fail' && $raw['spf_pass']) {
                $byIp[$ip]['spf_alignment_issue'] = true;
            }

            if ($dkimResult === 'fail' && $raw['dkim_pass']) {
                $byIp[$ip]['dkim_alignment_issue'] = true;
            }

            if ($headerFrom !== '') {
                $byIp[$ip]['header_from'][$headerFrom] = true;
            }

            $byIp[$ip]['days'][$day] = true;
        }

        $stats = [];

        foreach ($byIp as $ip => $acc) {
            $stats[] = new SourceStat(
                $ip,
                $acc['count'],
                $acc['pass'],
                $acc['both_failed'],
                $acc['spf_only_fail'],
                $acc['dkim_only_fail'],
                $acc['spf_alignment_issue'],
                $acc['dkim_alignment_issue'],
                array_keys($acc['header_from']),
                \count($acc['days']),
                $matcher->matchForDomain($ip, $domainId),
            );
        }

        return $stats;
    }

    /**
     * @param list<int> $recordIds
     * @return array<int, array{spf_pass: bool, dkim_pass: bool}>
     */
    private function fetchRawAuthResults(array $recordIds): array
    {
        if ($recordIds === []) {
            return [];
        }

        $placeholders = implode(',', array_fill(0, \count($recordIds), '?'));
        $stmt         = $this->pdo->prepare("SELECT record_id, type, result FROM auth_results WHERE record_id IN ($placeholders)");
        $stmt->execute($recordIds);

        $map = [];

        foreach ($stmt as $row) {
            $recordId = (int) $row['record_id'];
            $map[$recordId] ??= ['spf_pass' => false, 'dkim_pass' => false];

            if (strtolower((string) $row['result']) === 'pass') {
                if ($row['type'] === 'spf') {
                    $map[$recordId]['spf_pass'] = true;
                } elseif ($row['type'] === 'dkim') {
                    $map[$recordId]['dkim_pass'] = true;
                }
            }
        }

        return $map;
    }

    private function liveSpfLookupCount(string $domain): ?int
    {
        $result      = (new SpfCheck($this->dns))->run($domain);
        $lookupCount = $result[0]->detail['lookup_count'] ?? null;

        return \is_int($lookupCount) ? $lookupCount : null;
    }
}
