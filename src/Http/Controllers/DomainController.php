<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Auth\AuditLog;
use App\Auth\AuthUser;
use App\Auth\Roles;
use App\Auth\StepUp;
use App\Config;
use App\HealthCheck\Fix\DmarcFixSuggester;
use App\HealthCheck\Fix\HealthCheckFix;
use App\HealthCheck\Fix\MtaStsFixSuggester;
use App\HealthCheck\Fix\SpfFixSuggester;
use App\HealthCheck\Fix\TlsRptFixSuggester;
use App\HealthCheck\HealthCheckItemResult;
use App\HealthCheck\HealthCheckRepository;
use App\HealthCheck\HealthCheckRunnerFactory;
use App\HealthCheck\HealthCheckSummary;
use App\Http\AuthMiddleware;
use App\Http\SvgBarChart;
use App\Http\View;
use App\Recommendation\PolicyLevel;
use App\Recommendation\RecommendationRepository;
use App\Recommendation\RecommendationRow;
use App\Support\DomainName;
use App\Support\Ip;
use PDO;

/**
 * Domain list (spec §7.1) and per-domain drill-down (spec §7.2): overview
 * (policy/trend/health-check), source table, recommendations panel, recent
 * reports, a raw per-record report-detail view, and the mutating actions
 * (spec §15.1) split across two tiers — Admin (onboard/configure: `add()`,
 * `approveBaseline()`, `updatePolicy()`) and Super Admin (remove: the only
 * domain-management action reserved above Admin, plus the mirrored
 * `reactivate()`) — adding a domain (§11.1: runs a health check
 * synchronously so there's an immediate baseline), approving a domain's
 * current policy as the R9/alerting drift baseline (§10.6: never
 * silent/automatic), editing `target_policy`/`non_sending` post-onboarding,
 * and deactivating/reactivating a domain (§15.3: step-up-gated, a soft
 * `active` flip rather than a destructive delete so report/health-check
 * history is retained per §13 — every cron script already filters on
 * `active = 1`, so deactivation removes a domain from every pipeline, not
 * just the dashboard). The drill-down is addressed by query string
 * (`?domain=`) rather than a path param, since `Router` is exact-string-match
 * only.
 */
final class DomainController
{
    private const int TREND_WINDOW_DAYS      = 30;
    private const int SOURCE_ROW_LIMIT       = 200;
    private const int RECENT_REPORT_LIMIT    = 20;
    private const int CARD_TREND_WINDOW_DAYS = 14;
    private const int ATTENTION_LIMIT        = 8;
    private const int ACTIVITY_LIMIT         = 15;

    public function __construct(
        private readonly PDO $pdo,
        private readonly RecommendationRepository $recommendations,
        private readonly HealthCheckRepository $healthChecks,
        private readonly HealthCheckRunnerFactory $healthCheckFactory,
        private readonly AuditLog $audit,
        private readonly AuthMiddleware $auth,
        private readonly StepUp $stepUp,
        private readonly Config $config,
    ) {
    }

    public function index(AuthUser $user): void
    {
        $this->renderIndex($user);
    }

    public function add(AuthUser $actor): void
    {
        $domain = strtolower(trim((string) ($_POST['domain'] ?? '')));

        if (!DomainName::isValid($domain)) {
            $this->renderIndex($actor, error: 'Enter a valid domain name (e.g. example.com).');

            return;
        }

        $stmt = $this->pdo->prepare('SELECT id FROM domains WHERE domain = ?');
        $stmt->execute([$domain]);

        if ($stmt->fetch() !== false) {
            $this->renderIndex($actor, error: "\"$domain\" is already onboarded.");

            return;
        }

        $this->pdo->prepare('INSERT INTO domains (domain) VALUES (?)')->execute([$domain]);
        $domainId = (int) $this->pdo->lastInsertId();

        // Onboarding is a rare, deliberate admin action, not a hot path —
        // run the full check suite synchronously so there's an immediate
        // baseline (spec §11.1), rather than waiting for the next
        // scheduled/manual bin/healthcheck.php pass. 12 checks each
        // individually bounded by healthcheck.*_timeout_seconds can still
        // exceed a typical 30s request limit in the worst case.
        set_time_limit(120);

        $tally = ['pass' => 0, 'warn' => 0, 'fail' => 0, 'info' => 0, 'error' => 0];

        try {
            $items = $this->healthCheckFactory->forDomain($domainId)->run($domainId, $domain, 'onboarding');

            foreach ($items as $item) {
                $tally[$item->status] = ($tally[$item->status] ?? 0) + 1;
            }
        } catch (\Throwable) {
            // HealthCheckRunner already turns individual check failures into
            // 'error' items rather than throwing; a throw here would mean
            // something more fundamental broke. Onboarding still succeeded
            // (the domain row exists) — just note no health check ran yet.
        }

        $this->audit->record($actor->id, 'domain.onboarded', $domain, $tally, $this->clientIp());

        header('Location: /domain?' . http_build_query(['domain' => $domain]));
    }

    public function approveBaseline(AuthUser $actor): void
    {
        $domain = $this->findDomain((string) ($_POST['domain'] ?? ''));

        if ($domain === null) {
            $this->renderNotFound($actor, 'Domain not found.');

            return;
        }

        if ((int) $domain['active'] !== 1) {
            $this->renderDrillDown($actor, $domain, error: 'Reactivate this domain before approving a baseline.');

            return;
        }

        $policy = self::approvableBaseline(
            $domain['current_published_policy'] !== null ? (string) $domain['current_published_policy'] : null
        );

        if ($policy === null) {
            $this->renderDrillDown($actor, $domain, error: 'No published policy has been observed yet — run a health check first.');

            return;
        }

        $this->pdo->prepare('UPDATE domains SET approved_baseline_policy = ?, baseline_approved_at = NOW() WHERE id = ?')
            ->execute([$policy, (int) $domain['id']]);

        $this->audit->record($actor->id, 'domain.baseline_approved', (string) $domain['domain'], ['policy' => $policy], $this->clientIp());

        $domain['approved_baseline_policy'] = $policy;
        $this->renderDrillDown($actor, $domain, flash: "Approved \"$policy\" as the baseline.");
    }

    public function updatePolicy(AuthUser $actor): void
    {
        $domain = $this->findDomain((string) ($_POST['domain'] ?? ''));

        if ($domain === null) {
            $this->renderNotFound($actor, 'Domain not found.');

            return;
        }

        if ((int) $domain['active'] !== 1) {
            $this->renderDrillDown($actor, $domain, error: 'Reactivate this domain before editing its target policy.');

            return;
        }

        $targetPolicy = self::composeTargetPolicy(
            (string) ($_POST['target_p'] ?? ''),
            (string) ($_POST['target_sp'] ?? ''),
        );

        if ($targetPolicy === null) {
            $this->renderDrillDown($actor, $domain, error: 'Choose a valid level (none, quarantine, or reject) for both p and sp.');

            return;
        }

        $nonSending = isset($_POST['non_sending']) ? 1 : 0;

        $this->pdo->prepare('UPDATE domains SET target_policy = ?, non_sending = ? WHERE id = ?')
            ->execute([$targetPolicy, $nonSending, (int) $domain['id']]);

        $this->audit->record($actor->id, 'domain.policy_updated', (string) $domain['domain'], [
            'target_policy' => $targetPolicy,
            'non_sending'   => $nonSending,
        ], $this->clientIp());

        $domain['target_policy'] = $targetPolicy;
        $domain['non_sending']   = $nonSending;
        $this->renderDrillDown($actor, $domain, flash: "Target policy updated to \"$targetPolicy\".");
    }

    public function deactivate(AuthUser $actor): void
    {
        $domain = $this->findDomain((string) ($_POST['domain'] ?? ''));

        if ($domain === null) {
            $this->renderNotFound($actor, 'Domain not found.');

            return;
        }

        if (!$this->requireStepUp($actor, $domain)) {
            return;
        }

        if ((int) $domain['active'] !== 1) {
            $this->renderDrillDown($actor, $domain, error: 'Domain is already deactivated.');

            return;
        }

        $this->pdo->prepare('UPDATE domains SET active = 0 WHERE id = ?')->execute([(int) $domain['id']]);
        $this->audit->record($actor->id, 'domain.deactivated', (string) $domain['domain'], [], $this->clientIp());

        $domain['active'] = 0;
        $this->renderDrillDown(
            $actor,
            $domain,
            flash: 'Domain deactivated. It no longer appears on the domain list and is excluded from ingestion, health checks, analysis, and alerting.'
        );
    }

    public function reactivate(AuthUser $actor): void
    {
        $domain = $this->findDomain((string) ($_POST['domain'] ?? ''));

        if ($domain === null) {
            $this->renderNotFound($actor, 'Domain not found.');

            return;
        }

        if (!$this->requireStepUp($actor, $domain)) {
            return;
        }

        if ((int) $domain['active'] === 1) {
            $this->renderDrillDown($actor, $domain, error: 'Domain is already active.');

            return;
        }

        $this->pdo->prepare('UPDATE domains SET active = 1 WHERE id = ?')->execute([(int) $domain['id']]);
        $this->audit->record($actor->id, 'domain.reactivated', (string) $domain['domain'], [], $this->clientIp());

        $domain['active'] = 1;
        $this->renderDrillDown($actor, $domain, flash: 'Domain reactivated.');
    }

    /**
     * The one decision in approveBaseline(): a baseline is only approvable
     * once a published policy has actually been observed — spec §10.6
     * forbids ever seeding it silently/automatically.
     */
    public static function approvableBaseline(?string $currentPublishedPolicy): ?string
    {
        return $currentPublishedPolicy;
    }

    /**
     * The one decision in updatePolicy(): validate+compose the submitted
     * p/sp levels into the stored target_policy format, or refuse (null)
     * if either isn't one of PolicyLevel's recognized levels.
     */
    public static function composeTargetPolicy(string $p, string $sp): ?string
    {
        $p  = strtolower(trim($p));
        $sp = strtolower(trim($sp));

        if (!PolicyLevel::isValidLevel($p) || !PolicyLevel::isValidLevel($sp)) {
            return null;
        }

        return PolicyLevel::compose($p, $sp);
    }

    /**
     * Worst-status-wins grade for one health-check run's tally (spec
     * §7.1/§11) — extends healthStatusVariant()'s single-item convention
     * to a whole run: 'fail' outranks everything; 'error' (a blind spot,
     * never a pass, per §11.3) outranks 'warn'; 'warn' outranks
     * pass/info.
     *
     * @param array<string, int> $tally
     *
     * @return array{variant: string, label: string}
     */
    public static function healthGrade(array $tally): array
    {
        return match (true) {
            ($tally[HealthCheckItemResult::FAIL] ?? 0)  > 0 => ['variant' => 'danger', 'label' => 'Fail'],
            ($tally[HealthCheckItemResult::ERROR] ?? 0) > 0 => ['variant' => 'neutral', 'label' => 'Error'],
            ($tally[HealthCheckItemResult::WARN] ?? 0)  > 0 => ['variant' => 'warning', 'label' => 'Warn'],
            default                                         => ['variant' => 'success', 'label' => 'Pass'],
        };
    }

    /** @param array<string, mixed> $domain */
    private function requireStepUp(AuthUser $actor, array $domain): bool
    {
        if ($this->stepUp->verify($actor)) {
            return true;
        }

        $this->renderDrillDown($actor, $domain, error: 'Please re-verify (current password or passkey) to perform this action.');

        return false;
    }

    private function clientIp(): ?string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? null;

        return \is_string($ip) && $ip !== '' ? $ip : null;
    }

    /** spec §7.1 — the domain-list landing page. */
    private function renderIndex(AuthUser $user, ?string $flash = null, ?string $error = null): void
    {
        $domains = $this->pdo->query(
            'SELECT d.id,
                    d.domain,
                    d.current_published_policy,
                    d.target_policy,
                    (SELECT MAX(received_at) FROM reports r WHERE r.domain_id = d.id) AS last_report
               FROM domains d
              WHERE d.active = 1
              ORDER BY d.domain'
        )->fetchAll();

        $reportsLast7d = (int) $this->pdo->query(
            'SELECT COUNT(*) FROM reports WHERE received_at >= NOW() - INTERVAL 7 DAY'
        )->fetchColumn();
        $healthByDomain    = $this->healthChecks->latestForAllDomains();
        $recCountsByDomain = $this->recommendations->countsBySeverityForAllDomains();
        $trendByDomain     = $this->fetchCardTrendData();
        $ingestionHealth   = $this->fetchIngestionHealth();

        $lastHealthCheckAt = null;

        foreach ($healthByDomain as $h) {
            if ($lastHealthCheckAt === null || $h->runAt > $lastHealthCheckAt) {
                $lastHealthCheckAt = $h->runAt;
            }
        }

        $cards = '';

        foreach ($domains as $row) {
            $domainId  = (int) $row['id'];
            $published = $row['current_published_policy'] !== null ? (string) $row['current_published_policy'] : null;

            $grade = isset($healthByDomain[$domainId])
                ? self::healthGrade($healthByDomain[$domainId]->tally)
                : ['variant' => 'neutral', 'label' => 'Not checked'];

            $recCounts = $recCountsByDomain[$domainId] ?? [];
            $recBadges = '';

            foreach (['high', 'medium', 'low', 'info'] as $severity) {
                if (($recCounts[$severity] ?? 0) > 0) {
                    $variant = match ($severity) {
                        'high'   => 'danger',
                        'medium' => 'warning',
                        default  => 'neutral',
                    };
                    $recBadges .= View::badge($variant, $recCounts[$severity] . ' ' . ucfirst($severity));
                }
            }

            if ($recBadges === '') {
                $recBadges = '<span class="card-sub">No open recommendations</span>';
            }

            $cards .= '<div class="card posture-card">'
                . '<div class="posture-head"><a href="' . View::e('/domain?' . http_build_query(['domain' => $row['domain']])) . '">'
                . '<h2>' . View::e((string) $row['domain']) . '</h2></a>'
                . View::badge($grade['variant'], $grade['label']) . '</div>'
                . '<span class="policy-pill">' . View::e($published ?? 'not yet observed') . '</span>'
                . SvgBarChart::renderSparkline($trendByDomain[$domainId] ?? [])
                . '<div class="posture-recs">' . $recBadges . '</div>'
                . '</div>';
        }

        $body = '<div class="page-head"><div><h1>Domains' . View::helpTooltip('page-domains', 'What this page shows') . '</h1>'
            . '<div class="sub">' . \count($domains) . ' monitored domain' . (\count($domains) === 1 ? '' : 's') . '</div></div></div>';

        if ($error !== null) {
            $body .= '<p class="error">' . View::e($error) . '</p>';
        }

        $ingestBadge = match ($ingestionHealth['last_run_status']) {
            'ok'      => View::badge('success', $ingestionHealth['last_success_at'] ?? '—'),
            'error'   => View::badge('danger', 'Failed ' . ($ingestionHealth['last_run_at'] ?? '')),
            'running' => View::badge('neutral', 'Running'),
            default   => View::badge('neutral', 'Never run'),
        };

        $body .= '<div class="stats">'
            . '<div class="stat-tile"><div class="label">Domains monitored</div><div class="value">' . \count($domains) . '</div></div>'
            . '<div class="stat-tile"><div class="label">Reports, last 7 days</div><div class="value">' . $reportsLast7d . '</div></div>'
            . '<div class="stat-tile"><div class="label">Last ingestion</div><div class="value sm">' . $ingestBadge . '</div></div>'
            . '<div class="stat-tile"><div class="label">Last health check</div><div class="value mono sm">' . View::e($lastHealthCheckAt ?? 'never') . '</div></div>'
            . '</div>';

        $body .= '<div class="section-head"><h2>Domains</h2></div>'
            . '<div class="posture-grid">' . $cards . '</div>';

        $body .= $this->renderAttentionPanel() . $this->renderRecentActivity();

        if (Roles::atLeast($user->role, Roles::ADMIN)) {
            $body .= '<div class="narrow narrow-tight"><div class="card">'
                . '<h2>Add domain</h2>'
                . '<form method="post" action="/domains/add">'
                . View::csrfField($this->auth->csrfToken())
                . '<div class="field"><label for="domain">Domain</label><input type="text" id="domain" name="domain" placeholder="example.com" required></div>'
                . '<button type="submit" class="btn btn-primary btn-block">Add domain</button>'
                . '</form></div></div>';
        }

        $body .= '<script src="/assets/help.js"></script>';

        View::render('Domains', $body, $user, $this->auth->csrfToken(), $flash);
    }

    /**
     * Attention panel (spec §7.1): highest-severity open recommendations
     * across all domains. Sourced from persisted `recommendations`, not a
     * live re-run of the (deliberately stateless) alert checks — see
     * CLAUDE.md's Alerting section for why nothing there is persisted.
     */
    private function renderAttentionPanel(): string
    {
        $rows  = $this->recommendations->topOpenAcrossDomains(self::ATTENTION_LIMIT);
        $items = '';

        foreach ($rows as $entry) {
            $row     = $entry['row'];
            $subject = $row->subject !== null ? ' &middot; <span class="mono">' . View::e($row->subject) . '</span>' : '';

            $items .= '<div class="rec-item">'
                . View::badge($this->severityVariant($row->severity), strtoupper($row->severity))
                . '<span class="mono">' . View::e($entry['domain']) . '</span>'
                . '<span class="rec-rule">' . View::e($row->ruleId) . '</span>'
                . View::helpTooltip($this->ruleHelpSlug($row->ruleId), 'What triggers ' . $row->ruleId) . $subject
                . '<span class="rec-meta">last seen ' . View::e($row->lastSeen) . '</span>'
                . '</div>';
        }

        if ($items === '') {
            return '<div class="section-head"><h2>Attention</h2></div><p class="card-sub">No high/medium recommendations open.</p>';
        }

        return '<div class="section-head"><h2>Attention</h2></div><div class="rec-list">' . $items . '</div>';
    }

    /**
     * Recent activity (spec §7.1): domain onboarding/policy-change audit
     * entries plus newly seen unknown senders, merged and time-sorted.
     * "Policy changes detected" is admin-driven audit history here, not
     * DNS-observed drift — the latter is never persisted anywhere in the
     * app (see CLAUDE.md).
     */
    private function renderRecentActivity(): string
    {
        $relevantActions = ['domain.onboarded', 'domain.policy_updated', 'domain.baseline_approved'];

        $events = [];

        foreach ($this->audit->recent(self::ACTIVITY_LIMIT, 'domain.%') as $entry) {
            if (!\in_array($entry->action, $relevantActions, true)) {
                continue;
            }

            // The in_array() guard above already narrows $entry->action to
            // exactly these three values, so this match is exhaustive.
            $label = match ($entry->action) {
                'domain.onboarded'         => 'Domain onboarded',
                'domain.policy_updated'    => 'Target policy updated',
                'domain.baseline_approved' => 'Baseline approved',
            };

            $events[] = [
                'at'   => $entry->createdAt,
                'html' => '<span class="rec-rule">' . View::e($label) . '</span>'
                    . '<span class="mono">' . View::e($entry->target ?? '') . '</span>'
                    . '<span class="rec-meta">' . View::e($entry->createdAt) . '</span>',
            ];
        }

        foreach ($this->fetchNewlySeenUnknownSenders(self::ACTIVITY_LIMIT) as $sender) {
            $events[] = [
                'at'   => $sender['first_seen'],
                'html' => '<span class="rec-rule">New unknown sender</span>'
                    . '<span class="mono">' . View::e($sender['ip']) . '</span>'
                    . '<span class="rec-meta">' . View::e($sender['first_seen']) . '</span>',
            ];
        }

        usort($events, static fn (array $a, array $b): int => $b['at'] <=> $a['at']);
        $events = \array_slice($events, 0, self::ACTIVITY_LIMIT);

        if ($events === []) {
            return '<div class="section-head"><h2>Recent activity</h2></div><p class="card-sub">Nothing recent.</p>';
        }

        $items = '';

        foreach ($events as $event) {
            $items .= '<div class="rec-item">' . $event['html'] . '</div>';
        }

        return '<div class="section-head"><h2>Recent activity</h2></div><div class="rec-list">' . $items . '</div>';
    }

    public function show(AuthUser $user): void
    {
        $domain = $this->findDomain((string) ($_GET['domain'] ?? ''));

        if ($domain === null) {
            $this->renderNotFound($user, 'Domain not found.');

            return;
        }

        $this->renderDrillDown($user, $domain);
    }

    /** @param array<string, mixed> $domain */
    private function renderDrillDown(AuthUser $user, array $domain, ?string $flash = null, ?string $error = null): void
    {
        $domainId = (int) $domain['id'];
        $sort     = (string) ($_GET['sort'] ?? 'volume');
        $label    = isset($_GET['label']) && $_GET['label'] !== '' ? (string) $_GET['label'] : null;

        $notice = (int) $domain['active'] !== 1
            ? '<p class="error">This domain is deactivated — excluded from ingestion, health checks, analysis, and alerting. Historical data below is retained and still browsable.</p>'
            : '';

        $body = $notice
            . ($error !== null ? '<p class="error">' . View::e($error) . '</p>' : '')
            . $this->renderOverview(
                $user,
                $domain,
                $this->fetchTrendData($domainId),
                $this->healthChecks->latestForDomain($domainId),
            )
            . $this->renderSourceTable($this->fetchSourceRows($domainId, $sort, $label), (string) $domain['domain'], $sort, $label)
            . $this->renderRecommendations($this->recommendations->forDisplay($domainId))
            . $this->renderReportsList($this->fetchRecentReports($domainId), (string) $domain['domain'])
            . '<script src="/assets/help.js"></script>';

        View::render((string) $domain['domain'], $body, $user, $this->auth->csrfToken(), $flash);
    }

    public function reportDetail(AuthUser $user): void
    {
        $domain = $this->findDomain((string) ($_GET['domain'] ?? ''));

        if ($domain === null) {
            $this->renderNotFound($user, 'Domain not found.');

            return;
        }

        $reportId = (int) ($_GET['report_id'] ?? 0);

        // domain_id is part of the WHERE, not a separate check — a report_id
        // belonging to a different domain simply won't match (no IDOR).
        $stmt = $this->pdo->prepare(
            'SELECT id, reporter_org, report_id, date_begin, date_end FROM reports WHERE id = ? AND domain_id = ?'
        );
        $stmt->execute([$reportId, (int) $domain['id']]);
        $report = $stmt->fetch();

        if ($report === false) {
            $this->renderNotFound($user, 'Report not found for this domain.');

            return;
        }

        $body = '<div class="page-head"><div><h1>Report detail' . View::helpTooltip('page-report-detail', 'What this page shows') . '</h1>'
            . '<div class="sub"><a href="' . View::e('/domain?' . http_build_query(['domain' => $domain['domain']])) . '">&larr; Back to '
            . View::e((string) $domain['domain']) . '</a></div></div></div>'
            . $this->renderReportMeta($report)
            . $this->renderRecordDetail($this->fetchReportRecords($reportId))
            . '<script src="/assets/help.js"></script>';

        View::render('Report detail', $body, $user, $this->auth->csrfToken());
    }

    /** @return array<string, mixed>|null */
    private function findDomain(string $domain): ?array
    {
        $domain = strtolower(trim($domain));

        if ($domain === '') {
            return null;
        }

        $stmt = $this->pdo->prepare(
            'SELECT id, domain, current_published_policy, approved_baseline_policy, target_policy, non_sending, active
               FROM domains WHERE domain = ?'
        );
        $stmt->execute([$domain]);
        $row = $stmt->fetch();

        return $row === false ? null : $row;
    }

    private function renderNotFound(AuthUser $user, string $message): void
    {
        http_response_code(404);
        $body = '<div class="page-head"><div><h1>Not found</h1><div class="sub">' . View::e($message) . '</div></div></div>';
        View::render('Not found', $body, $user, $this->auth->csrfToken());
    }

    /** @return list<array{day: string, passed: int, failed: int}> */
    private function fetchTrendData(int $domainId): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT DATE(r.date_begin) AS day,
                    SUM(CASE WHEN rr.dkim_result = 'pass' OR rr.spf_result = 'pass' THEN rr.`count` ELSE 0 END) AS passed,
                    SUM(CASE WHEN NOT (rr.dkim_result = 'pass' OR rr.spf_result = 'pass') THEN rr.`count` ELSE 0 END) AS failed
               FROM report_records rr
               JOIN reports r ON r.id = rr.report_id
              WHERE r.domain_id = ? AND r.date_begin >= NOW() - INTERVAL " . self::TREND_WINDOW_DAYS . ' DAY
              GROUP BY DATE(r.date_begin)
              ORDER BY day'
        );
        $stmt->bindValue(1, $domainId, PDO::PARAM_INT);
        $stmt->execute();

        $days = [];

        foreach ($stmt as $row) {
            $days[] = ['day' => (string) $row['day'], 'passed' => (int) $row['passed'], 'failed' => (int) $row['failed']];
        }

        return $days;
    }

    /** @return list<array<string, mixed>> */
    private function fetchSourceRows(int $domainId, string $sort, ?string $label): array
    {
        $orderBy = match ($sort) {
            'ip'    => 'rr.source_ip ASC',
            'label' => 'label ASC, volume DESC',
            'dkim'  => 'dkim_pass DESC',
            'spf'   => 'spf_pass DESC',
            default => 'volume DESC',
        };

        $sql = "SELECT rr.source_ip AS source_ip, ie.rdns AS rdns, ie.asn_org AS asn_org,
                       COALESCE(ie.label, 'pending') AS label,
                       SUM(rr.`count`) AS volume,
                       SUM(CASE WHEN rr.dkim_result = 'pass' THEN rr.`count` ELSE 0 END) AS dkim_pass,
                       SUM(CASE WHEN rr.spf_result = 'pass' THEN rr.`count` ELSE 0 END) AS spf_pass
                  FROM report_records rr
                  JOIN reports r ON r.id = rr.report_id
                  LEFT JOIN ip_enrichment ie ON ie.source_ip = rr.source_ip
                 WHERE r.domain_id = ? AND r.date_begin >= NOW() - INTERVAL " . self::TREND_WINDOW_DAYS . ' DAY';

        $params = [$domainId];

        if ($label !== null) {
            $sql .= " AND COALESCE(ie.label, 'pending') = ?";
            $params[] = $label;
        }

        $sql .= ' GROUP BY rr.source_ip, ie.rdns, ie.asn_org, ie.label ORDER BY ' . $orderBy . ' LIMIT ' . self::SOURCE_ROW_LIMIT;

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll();

        foreach ($rows as &$row) {
            $row['ip'] = Ip::toString((string) $row['source_ip']);
        }

        unset($row);

        return $rows;
    }

    /** @return list<array<string, mixed>> */
    private function fetchRecentReports(int $domainId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT r.id, r.reporter_org, r.date_begin, r.date_end,
                    (SELECT COUNT(*) FROM report_records rr WHERE rr.report_id = r.id) AS record_count
               FROM reports r
              WHERE r.domain_id = ?
              ORDER BY r.date_begin DESC
              LIMIT ' . self::RECENT_REPORT_LIMIT
        );
        $stmt->execute([$domainId]);

        return $stmt->fetchAll();
    }

    /** @return list<array<string, mixed>> */
    private function fetchReportRecords(int $reportId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, source_ip, `count`, disposition, dkim_result, spf_result, header_from
               FROM report_records WHERE report_id = ? ORDER BY `count` DESC'
        );
        $stmt->execute([$reportId]);
        $records = $stmt->fetchAll();

        if ($records === []) {
            return [];
        }

        $recordIds    = array_map(static fn (array $r): int => (int) $r['id'], $records);
        $placeholders = implode(',', array_fill(0, \count($recordIds), '?'));
        $stmt         = $this->pdo->prepare("SELECT record_id, type, domain, selector, result FROM auth_results WHERE record_id IN ($placeholders)");
        $stmt->execute($recordIds);

        $authByRecord = [];

        foreach ($stmt as $row) {
            $authByRecord[(int) $row['record_id']][] = $row;
        }

        foreach ($records as &$r) {
            $r['source_ip']    = Ip::toString((string) $r['source_ip']);
            $r['auth_results'] = $authByRecord[(int) $r['id']] ?? [];
        }

        unset($r);

        return $records;
    }

    /**
     * Bulk cross-domain trend data for the overview posture-card grid
     * (spec §7.1) — one query for every active domain rather than
     * fetchTrendData() called N times per page load.
     *
     * @return array<int, list<array{day: string, passed: int, failed: int}>> domain_id => days
     */
    private function fetchCardTrendData(): array
    {
        $stmt = $this->pdo->query(
            "SELECT r.domain_id AS domain_id,
                    DATE(r.date_begin) AS day,
                    SUM(CASE WHEN rr.dkim_result = 'pass' OR rr.spf_result = 'pass' THEN rr.`count` ELSE 0 END) AS passed,
                    SUM(CASE WHEN NOT (rr.dkim_result = 'pass' OR rr.spf_result = 'pass') THEN rr.`count` ELSE 0 END) AS failed
               FROM report_records rr
               JOIN reports r ON r.id = rr.report_id
               JOIN domains d ON d.id = r.domain_id AND d.active = 1
              WHERE r.date_begin >= NOW() - INTERVAL " . self::CARD_TREND_WINDOW_DAYS . ' DAY
              GROUP BY r.domain_id, DATE(r.date_begin)
              ORDER BY r.domain_id, day'
        );

        $byDomain = [];

        foreach ($stmt as $row) {
            $byDomain[(int) $row['domain_id']][] = [
                'day'    => (string) $row['day'],
                'passed' => (int) $row['passed'],
                'failed' => (int) $row['failed'],
            ];
        }

        return $byDomain;
    }

    /**
     * Last ingestion run's status/timestamp, and the last *successful*
     * run's timestamp separately — the overview dashboard's ingestion
     * health indicator (spec §7.1, ties to the heartbeat alert, §8).
     *
     * @return array{last_success_at: ?string, last_run_status: ?string, last_run_at: ?string}
     */
    private function fetchIngestionHealth(): array
    {
        $last = $this->pdo->query(
            'SELECT status, finished_at FROM ingest_runs ORDER BY id DESC LIMIT 1'
        )->fetch();

        $lastSuccessAt = $this->pdo->query(
            "SELECT MAX(finished_at) FROM ingest_runs WHERE status = 'ok'"
        )->fetchColumn();

        return [
            'last_success_at' => $lastSuccessAt !== false && $lastSuccessAt !== null ? (string) $lastSuccessAt : null,
            'last_run_status' => $last          !== false ? (string) $last['status'] : null,
            'last_run_at'     => $last          !== false && $last['finished_at'] !== null ? (string) $last['finished_at'] : null,
        ];
    }

    /**
     * IPs first observed as 'unknown' recently — the overview dashboard's
     * recent-activity feed (spec §7.1). Uses ip_enrichment.first_seen,
     * which ReportStore::touchEnrichment() only ever sets on first
     * INSERT, never on subsequent updates.
     *
     * @return list<array{ip: string, first_seen: string}>
     */
    private function fetchNewlySeenUnknownSenders(int $limit): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT source_ip, first_seen FROM ip_enrichment
              WHERE first_seen IS NOT NULL AND label = 'unknown'
              ORDER BY first_seen DESC LIMIT ?"
        );
        $stmt->bindValue(1, $limit, PDO::PARAM_INT);
        $stmt->execute();

        $senders = [];

        foreach ($stmt as $row) {
            $senders[] = ['ip' => Ip::toString((string) $row['source_ip']), 'first_seen' => (string) $row['first_seen']];
        }

        return $senders;
    }

    /**
     * @param array<string, mixed> $domain
     * @param list<array{day: string, passed: int, failed: int}> $trend
     */
    private function renderOverview(AuthUser $user, array $domain, array $trend, ?HealthCheckSummary $health): string
    {
        $current     = $domain['current_published_policy'] !== null ? (string) $domain['current_published_policy'] : 'not yet observed';
        $baseline    = $domain['approved_baseline_policy'] !== null ? (string) $domain['approved_baseline_policy'] : 'none approved';
        $target      = (string) $domain['target_policy'];
        $active      = (int) $domain['active'] === 1;
        $csrf        = $this->auth->csrfToken();
        $domainField = '<input type="hidden" name="domain" value="' . View::e((string) $domain['domain']) . '">';
        $stepUpAttr  = $this->stepUp->formAttr($user);

        $statusForm = '';

        if (Roles::atLeast($user->role, Roles::SUPER_ADMIN)) {
            $statusForm = $active
                ? '<form method="post" action="/domain/deactivate" class="inline-form"' . $stepUpAttr . '>'
                    . View::csrfField($csrf) . $domainField . $this->stepUp->fieldHtml($user)
                    . '<button type="submit" class="btn btn-danger btn-sm">Deactivate</button></form>'
                : '<form method="post" action="/domain/reactivate" class="inline-form"' . $stepUpAttr . '>'
                    . View::csrfField($csrf) . $domainField . $this->stepUp->fieldHtml($user)
                    . '<button type="submit" class="btn btn-secondary btn-sm">Reactivate</button></form>';
        }

        $approveForm = '';

        if ($active && $domain['current_published_policy'] !== null && Roles::atLeast($user->role, Roles::ADMIN)) {
            $approveForm = '<form method="post" action="/domain/approve-baseline" class="inline-form">'
                . View::csrfField($csrf) . $domainField
                . '<button type="submit" class="btn btn-secondary btn-sm">Approve as baseline</button>'
                . '</form>';
        }

        $policyCard = '<div class="card"><h2>Policy' . View::helpTooltip('card-policy', 'What this card shows') . '</h2>'
            . '<div class="policy-row"><span class="policy-label">Status</span>'
            . View::badge($active ? 'success' : 'neutral', $active ? 'Active' : 'Deactivated') . $statusForm . '</div>'
            . '<div class="policy-row"><span class="policy-label">Published</span><span class="policy-pill">' . View::e($current) . '</span>' . $approveForm . '</div>'
            . '<div class="policy-row"><span class="policy-label">Approved baseline</span><span class="policy-pill">' . View::e($baseline) . '</span></div>'
            . '<div class="policy-row"><span class="policy-label">Target</span><span class="policy-pill">' . View::e($target) . '</span></div>'
            . '</div>';

        $policyEditCard = '';

        if ($active && Roles::atLeast($user->role, Roles::ADMIN)) {
            $currentP  = PolicyLevel::extract($target)                ?? 'reject';
            $currentSp = PolicyLevel::extractSubdomainPolicy($target) ?? 'reject';

            $policyEditCard = '<div class="card">'
                . '<h2>Edit target policy' . View::helpTooltip('card-edit-target-policy', 'What this form does') . '</h2>'
                . '<form method="post" action="/domain/policy">'
                . View::csrfField($csrf) . $domainField
                . '<div class="field"><label for="target_p">p (domain policy)</label>'
                . '<select id="target_p" name="target_p">' . $this->levelOptions($currentP) . '</select></div>'
                . '<div class="field"><label for="target_sp">sp (subdomain policy)</label>'
                . '<select id="target_sp" name="target_sp">' . $this->levelOptions($currentSp) . '</select></div>'
                . '<div class="field"><label class="checkbox-label"><input type="checkbox" name="non_sending" value="1"'
                . ((int) $domain['non_sending'] === 1 ? ' checked' : '') . '> Non-sending domain (enables R10)</label></div>'
                . '<button type="submit" class="btn btn-secondary btn-sm">Save</button>'
                . '</form></div>';
        }

        $chartCard = '<div class="card chart-card"><h2>Pass/fail volume, last ' . self::TREND_WINDOW_DAYS . ' days'
            . View::helpTooltip('card-pass-fail-chart', 'What this chart shows') . '</h2>'
            . SvgBarChart::render($trend) . '</div>';

        $authRecordCard = '';
        $mailFrom       = (string) $this->config->require('app.mail_from');
        $authRecord     = self::crossDomainAuthRecord((string) $domain['domain'], $mailFrom);

        if ($authRecord !== null) {
            $authRecordCard = '<div class="card">'
                . '<h2>Cross-domain report authorization' . View::helpTooltip('hc-report-auth', 'What this record does') . '</h2>'
                . '<p class="card-sub">To have <strong>this tool</strong> receive ' . View::e((string) $domain['domain'])
                . '&rsquo;s reports, its DMARC record needs <code>rua=mailto:' . View::e($mailFrom)
                . '</code> — then add this TXT record so receivers actually send them here (spec §11.2). This is independent of the'
                . ' health check\'s own "report destination auth" result above, which verifies whatever destination the domain\'s'
                . ' rua= <em>currently</em> points to, not this tool specifically.</p>'
                . '<code class="rec-evidence">' . View::e($authRecord['name']) . '  IN TXT  &quot;' . View::e($authRecord['value']) . '&quot;</code>'
                . '</div>';
        }

        return '<div class="page-head"><div><h1>' . View::e((string) $domain['domain']) . View::helpTooltip('page-domain-detail', 'What this page shows') . '</h1>'
            . '<div class="sub"><a href="/">&larr; All domains</a></div></div></div>'
            . '<div class="overview-grid">'
            . '<div class="overview-col">' . $policyCard . $policyEditCard . '</div>'
            . '<div class="overview-col">' . $chartCard . $authRecordCard . '</div>'
            . '</div>'
            . $this->renderHealthCheck($health, (string) $domain['domain'], $mailFrom)
            . ($statusForm !== '' ? '<script src="/assets/webauthn.js"></script>' : '');
    }

    /**
     * The exact TXT record an operator adds to the report-*receiving*
     * domain's DNS to authorize accepting reports for $policyDomain (spec
     * §11.2) — null when no cross-domain authorization is needed (same
     * domain, or the mailbox address has no domain part to extract).
     *
     * @return array{name: string, value: string}|null
     */
    public static function crossDomainAuthRecord(string $policyDomain, string $mailboxAddress): ?array
    {
        $policyDomain  = strtolower(trim($policyDomain));
        $at            = strrpos($mailboxAddress, '@');
        $mailboxDomain = $at !== false ? strtolower(substr($mailboxAddress, $at + 1)) : '';

        if ($policyDomain === '' || $mailboxDomain === '' || $policyDomain === $mailboxDomain) {
            return null;
        }

        return ['name' => $policyDomain . '._report._dmarc.' . $mailboxDomain, 'value' => 'v=DMARC1'];
    }

    private function levelOptions(string $selected): string
    {
        $html = '';

        foreach (['none', 'quarantine', 'reject'] as $level) {
            $html .= '<option value="' . $level . '"' . ($selected === $level ? ' selected' : '') . '>' . ucfirst($level) . '</option>';
        }

        return $html;
    }

    private function renderHealthCheck(?HealthCheckSummary $health, string $domain, string $mailFrom): string
    {
        $sectionTitle = '<h2>Health check' . View::helpTooltip('card-health-check', 'What this section shows') . '</h2>';

        if ($health === null) {
            return '<div class="section-head">' . $sectionTitle . '</div><p class="card-sub">No health check has been run yet.</p>';
        }

        $mxHosts = [];

        foreach ($health->items as $item) {
            if ($item->checkName === 'mx' && isset($item->detail['hosts']) && \is_array($item->detail['hosts'])) {
                foreach ($item->detail['hosts'] as $mx) {
                    if (\is_array($mx) && isset($mx['host']) && \is_string($mx['host'])) {
                        $mxHosts[] = $mx['host'];
                    }
                }
            }
        }

        $items = '';

        foreach ($health->items as $index => $item) {
            $helpSlug = $this->healthCheckHelpSlug($item->checkName);
            $reason   = isset($item->detail['reason']) ? (string) $item->detail['reason'] : null;
            $fixes    = $this->suggestFix($item->checkName, $item->detail, $domain, $mailFrom, $mxHosts);

            $items .= '<div class="health-item">'
                . View::badge($this->healthStatusVariant($item->status), $item->checkName)
                . ($helpSlug !== null ? View::helpTooltip($helpSlug, 'What the ' . $item->checkName . ' check does') : '')
                . '<span class="health-category">' . View::e($item->category) . '</span>'
                . ($reason !== null ? '<span class="health-reason">' . View::e($reason) . '</span>' : '')
                . $this->renderFixTrigger($fixes, 'fix-tpl-' . $index)
                . '</div>';
        }

        return '<div class="section-head">' . $sectionTitle
            . '<span class="sub">Last run ' . View::e($health->runAt) . ' (' . View::e($health->trigger) . ')</span></div>'
            . '<div class="health-grid">' . $items . '</div>';
    }

    private function healthStatusVariant(string $status): string
    {
        return match ($status) {
            HealthCheckItemResult::PASS => 'success',
            HealthCheckItemResult::WARN => 'warning',
            HealthCheckItemResult::FAIL => 'danger',
            // info, error — error must never render as a pass (spec §11.3)
            default => 'neutral',
        };
    }

    /**
     * checkName -> src/Help/content/healthcheck.php (or dmarc/spf/dkim.php)
     * slug. Some checkNames share a topic with an existing fundamentals
     * article (spf/dkim/dmarc) rather than needing a duplicate hc-* one;
     * null means no article covers that checkName yet — skip the tooltip
     * rather than link a dead slug.
     */
    private function healthCheckHelpSlug(string $checkName): ?string
    {
        return match ($checkName) {
            'mx', 'mx_resolution'     => 'hc-mx',
            'spf'                     => 'spf-overview',
            'dkim'                    => 'dkim-overview',
            'dmarc'                   => 'dmarc-overview',
            'dnssec'                  => 'hc-dnssec',
            'mta_sts'                 => 'hc-mta-sts',
            'tls_rpt'                 => 'hc-tls-rpt',
            'bimi'                    => 'hc-bimi',
            'starttls'                => 'hc-starttls',
            'dnsbl_zen'               => 'hc-dnsbl',
            'dnsbl_dbl'               => 'hc-rhsbl',
            'fcrdns'                  => 'hc-fcrdns',
            'report_destination_auth' => 'hc-report-auth',
            default                   => null,
        };
    }

    /**
     * Dispatches to the matching src/HealthCheck/Fix/*Suggester for a
     * mechanically-generatable DNS fix — generation/copy only, never
     * applied to any nameserver. Most checkNames have no deterministic fix
     * (blocklist listings, cert problems, etc.) and return [] here.
     *
     * @param array<string, mixed> $detail
     * @param list<string> $mxHosts
     *
     * @return list<HealthCheckFix>
     */
    private function suggestFix(string $checkName, array $detail, string $domain, string $mailFrom, array $mxHosts): array
    {
        return match ($checkName) {
            'spf'     => SpfFixSuggester::suggest($domain, $detail),
            'dmarc'   => DmarcFixSuggester::suggest($domain, $detail, $mailFrom),
            'tls_rpt' => TlsRptFixSuggester::suggest($domain, $detail, $mailFrom),
            'mta_sts' => MtaStsFixSuggester::suggest($domain, $detail, $mxHosts),
            default   => [],
        };
    }

    /** @param list<HealthCheckFix> $fixes */
    /**
     * Renders a "Fix me" button + a hidden <template> holding the actual
     * fix content — help.js clones the template into a floating popover on
     * click (same mechanism as the "?" tooltips), rather than rendering the
     * fix inline. .health-grid is a CSS grid, and any in-flow content
     * growth in one cell inflates the whole row to match — the exact bug
     * already fixed once for the tooltip popover, recurring here until the
     * fix content stopped living in normal document flow at all.
     *
     * @param list<HealthCheckFix> $fixes
     */
    private function renderFixTrigger(array $fixes, string $templateId): string
    {
        if ($fixes === []) {
            return '';
        }

        $blocks = '';

        foreach ($fixes as $fix) {
            // &#10; not a raw \n — a literal newline inside an HTML attribute
            // value has inconsistent cross-browser normalization; the numeric
            // character reference is unambiguously decoded back to LF when
            // JS reads button.dataset.copyValue, matters for the multi-line
            // MTA-STS policy-file fix.
            $copyValue = str_replace("\n", '&#10;', View::e($fix->recordValue));

            $blocks .= '<div class="fix-block">'
                . '<div class="fix-label">' . View::e($fix->label) . '</div>'
                . '<code class="rec-evidence">' . View::e($fix->recordName) . '  ' . View::e($fix->recordType)
                . '  &quot;' . View::e($fix->recordValue) . '&quot;</code>'
                . '<p class="card-sub">' . View::e($fix->note) . '</p>'
                . '<button type="button" class="btn btn-secondary btn-sm copy-btn" data-copy-value="' . $copyValue . '">Copy</button>'
                . '</div>';
        }

        return '<button type="button" class="btn btn-secondary btn-sm fix-trigger" data-fix-target="' . View::e($templateId) . '">Fix me</button>'
            . '<template id="' . View::e($templateId) . '">' . $blocks . '</template>';
    }

    /** @param list<array<string, mixed>> $rows */
    private function renderSourceTable(array $rows, string $domain, string $sort, ?string $label): string
    {
        $sortLink = static function (string $key, string $text) use ($domain, $sort, $label): string {
            $params          = ['domain' => $domain, 'sort' => $key];
            $params['label'] = $label ?? '';
            $active          = $sort === $key ? ' class="active"' : '';

            return '<a href="/domain?' . http_build_query($params) . '"' . $active . '>' . View::e($text) . '</a>';
        };

        $labels = array_values(array_unique(array_map(static fn (array $r): string => (string) $r['label'], $rows)));
        sort($labels);

        $filterLinks = '<a href="/domain?' . http_build_query(['domain' => $domain, 'sort' => $sort]) . '"'
            . ($label === null ? ' class="active"' : '') . '>All</a>';

        foreach ($labels as $l) {
            $active = $label === $l ? ' class="active"' : '';
            $filterLinks .= ' <a href="/domain?' . http_build_query(['domain' => $domain, 'sort' => $sort, 'label' => $l]) . '"' . $active . '>' . View::e($l) . '</a>';
        }

        $tr = '';

        foreach ($rows as $r) {
            $volume  = (int) $r['volume'];
            $dkimPct = $volume > 0 ? (int) round(((int) $r['dkim_pass']) / $volume * 100) : 0;
            $spfPct  = $volume > 0 ? (int) round(((int) $r['spf_pass']) / $volume * 100) : 0;

            $tr .= sprintf(
                '<tr><td class="mono">%s</td><td>%s</td><td>%s</td><td>%s</td>'
                    . '<td class="mono num">%d</td>'
                    . '<td class="num">%d%%</td><td class="num">%d%%</td></tr>',
                View::e((string) $r['ip']),
                View::e($r['rdns'] !== null ? (string) $r['rdns'] : '—'),
                View::e($r['asn_org'] !== null ? (string) $r['asn_org'] : '—'),
                View::badge($this->labelVariant((string) $r['label']), (string) $r['label']),
                $volume,
                $dkimPct,
                $spfPct,
            );
        }

        return '<div class="section-head"><h2>Sources' . View::helpTooltip('card-sources', 'What this table shows') . '</h2><div class="table-filters">' . $filterLinks . '</div></div>'
            . '<div class="table-card"><div class="table-scroll"><table><thead><tr>'
            . '<th>' . $sortLink('ip', 'IP') . '</th><th>rDNS</th><th>ASN org</th>'
            . '<th>' . $sortLink('label', 'Label') . View::helpTooltip('known-vs-unknown', 'What known/unknown labels mean') . '</th>'
            . '<th>' . $sortLink('volume', 'Volume') . '</th>'
            . '<th>' . $sortLink('dkim', 'DKIM pass') . View::helpTooltip('dkim-overview', 'What DKIM pass means') . '</th>'
            . '<th>' . $sortLink('spf', 'SPF pass') . View::helpTooltip('spf-overview', 'What SPF pass means') . '</th>'
            . '</tr></thead><tbody>' . ($tr !== '' ? $tr : '<tr><td colspan="7" class="empty">No sources in the last ' . self::TREND_WINDOW_DAYS . ' days.</td></tr>') . '</tbody></table></div></div>';
    }

    private function labelVariant(string $label): string
    {
        return match ($label) {
            'unknown' => 'unknown',
            'pending' => 'neutral',
            default   => 'success', // any known_senders/ESP label
        };
    }

    /** @param list<RecommendationRow> $rows */
    private function renderRecommendations(array $rows): string
    {
        $sectionTitle = '<h2>Recommendations' . View::helpTooltip('card-recommendations', 'What this section shows') . '</h2>';

        if ($rows === []) {
            return '<div class="section-head">' . $sectionTitle . '</div><p class="card-sub">No open recommendations.</p>';
        }

        $items = '';

        foreach ($rows as $row) {
            $subject  = $row->subject !== null ? ' &middot; <span class="mono">' . View::e($row->subject) . '</span>' : '';
            $evidence = View::e(json_encode($row->evidence, JSON_THROW_ON_ERROR));

            $items .= '<div class="rec-item">'
                . View::badge($this->severityVariant($row->severity), strtoupper($row->severity))
                . '<span class="rec-rule">' . View::e($row->ruleId) . '</span>'
                . View::helpTooltip($this->ruleHelpSlug($row->ruleId), 'What triggers ' . $row->ruleId) . $subject
                . '<span class="rec-meta">first seen ' . View::e($row->firstSeen) . ' &middot; last seen ' . View::e($row->lastSeen) . '</span>'
                . '<code class="rec-evidence">' . $evidence . '</code>'
                . '</div>';
        }

        return '<div class="section-head">' . $sectionTitle . '</div><div class="rec-list">' . $items . '</div>';
    }

    private function severityVariant(string $severity): string
    {
        return match ($severity) {
            'high'   => 'danger',
            'medium' => 'warning',
            default  => 'neutral', // low, info
        };
    }

    /** "R1".."R12" -> the matching src/Help/content/rules.php slug. */
    private function ruleHelpSlug(string $ruleId): string
    {
        return 'rule-' . strtolower($ruleId);
    }

    /** @param list<array<string, mixed>> $reports */
    private function renderReportsList(array $reports, string $domain): string
    {
        $rows = '';

        foreach ($reports as $r) {
            $rows .= sprintf(
                '<tr><td>%s</td><td class="mono">%s</td><td class="mono">%s</td><td class="num">%d</td><td><a href="%s">View</a></td></tr>',
                View::e((string) $r['reporter_org']),
                View::e((string) $r['date_begin']),
                View::e((string) $r['date_end']),
                (int) $r['record_count'],
                View::e('/domain/report?' . http_build_query(['domain' => $domain, 'report_id' => $r['id']])),
            );
        }

        return '<div class="section-head"><h2>Recent reports' . View::helpTooltip('card-recent-reports', 'What this section shows') . '</h2></div>'
            . '<div class="table-card"><div class="table-scroll"><table><thead><tr>'
            . '<th>Reporter</th><th>Period start</th><th>Period end</th><th>Records</th><th></th>'
            . '</tr></thead><tbody>' . ($rows !== '' ? $rows : '<tr><td colspan="5" class="empty">No reports yet.</td></tr>') . '</tbody></table></div></div>';
    }

    /** @param array<string, mixed> $report */
    private function renderReportMeta(array $report): string
    {
        return '<div class="stats">'
            . $this->statTile('Reporter', (string) $report['reporter_org'])
            . $this->statTile('Report ID', (string) $report['report_id'])
            . $this->statTile('Period start', (string) $report['date_begin'])
            . $this->statTile('Period end', (string) $report['date_end'])
            . '</div>';
    }

    private function statTile(string $label, string $value): string
    {
        return '<div class="stat-tile"><div class="label">' . View::e($label) . '</div>'
            . '<div class="value mono sm">' . View::e($value) . '</div></div>';
    }

    /** @param list<array<string, mixed>> $records */
    private function renderRecordDetail(array $records): string
    {
        if ($records === []) {
            return '<p class="card-sub">No records in this report.</p>';
        }

        $rows = '';

        foreach ($records as $r) {
            $authRows = '';

            /** @var list<array<string, mixed>> $authResults */
            $authResults = $r['auth_results'];

            foreach ($authResults as $a) {
                $authRows .= sprintf(
                    '<div class="auth-row"><span class="mono">%s</span> domain=<span class="mono">%s</span> selector=<span class="mono">%s</span> result=<span class="mono">%s</span></div>',
                    View::e((string) $a['type']),
                    View::e($a['domain'] !== null ? (string) $a['domain'] : '—'),
                    View::e($a['selector'] !== null ? (string) $a['selector'] : '—'),
                    View::e($a['result'] !== null ? (string) $a['result'] : '—'),
                );
            }

            $rows .= sprintf(
                '<tr><td class="mono">%s</td><td class="num">%d</td><td>%s</td><td>%s</td><td>%s</td><td class="mono">%s</td></tr>'
                    . '<tr class="auth-details"><td colspan="6">%s</td></tr>',
                View::e((string) $r['source_ip']),
                (int) $r['count'],
                View::badge($this->dispositionVariant((string) $r['disposition']), (string) $r['disposition']),
                View::badge($r['dkim_result'] === 'pass' ? 'success' : 'danger', (string) $r['dkim_result']),
                View::badge($r['spf_result'] === 'pass' ? 'success' : 'danger', (string) $r['spf_result']),
                View::e($r['header_from'] !== null ? (string) $r['header_from'] : '—'),
                $authRows !== '' ? $authRows : '<span class="card-sub">No raw auth_results recorded.</span>',
            );
        }

        return '<div class="table-card"><div class="table-scroll"><table><thead><tr>'
            . '<th>Source IP</th><th>Count</th><th>Disposition</th><th>DKIM</th><th>SPF</th><th>Header From</th>'
            . '</tr></thead><tbody>' . $rows . '</tbody></table></div></div>';
    }

    private function dispositionVariant(string $disposition): string
    {
        return match ($disposition) {
            'reject'     => 'danger',
            'quarantine' => 'warning',
            default      => 'success', // none
        };
    }
}
