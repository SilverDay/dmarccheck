<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Auth\AuthUser;
use App\Auth\Roles;
use App\Http\View;
use App\Reports\ReportSearchCriteria;
use App\Reports\ReportSearchCsv;
use App\Reports\ReportSearchRepository;
use InvalidArgumentException;

final class ReportSearchController
{
    private const int PAGE_LIMIT   = 200;
    private const int EXPORT_LIMIT = 10000;

    public function __construct(private readonly ReportSearchRepository $reports)
    {
    }

    public function index(AuthUser $user): void
    {
        try {
            $criteria = ReportSearchCriteria::fromQuery($_GET);
        } catch (InvalidArgumentException $e) {
            http_response_code(400);
            $this->render($user, null, [], $e->getMessage());

            return;
        }

        if ($criteria->domainId === null && !Roles::atLeast($user->role, Roles::ADMIN)) {
            $this->render($user, $criteria, [], null, 'Choose one domain. Cross-domain search is available to Admin and Super Admin.');

            return;
        }

        $rows        = $this->reports->search($criteria, self::PAGE_LIMIT + 1);
        $truncated   = \count($rows) > self::PAGE_LIMIT;
        $displayRows = \array_slice($rows, 0, self::PAGE_LIMIT);
        $this->render(
            $user,
            $criteria,
            $displayRows,
            null,
            null,
            $truncated ? 'Showing the first 200 matching records. Narrow filters or download the CSV (maximum 10,000 rows).' : null
        );
    }

    public function export(AuthUser $user): void
    {
        try {
            $criteria = ReportSearchCriteria::fromQuery($_GET);
        } catch (InvalidArgumentException $e) {
            http_response_code(400);
            header('Content-Type: text/plain; charset=utf-8');
            echo $e->getMessage() . "\n";

            return;
        }

        if ($criteria->domainId === null && !Roles::atLeast($user->role, Roles::ADMIN)) {
            http_response_code(403);
            header('Content-Type: text/plain; charset=utf-8');
            echo "Cross-domain search is available to Admin and Super Admin only.\n";

            return;
        }

        $rows      = $this->reports->search($criteria, self::EXPORT_LIMIT + 1);
        $truncated = \count($rows) > self::EXPORT_LIMIT;
        $csv       = ReportSearchCsv::render(\array_slice($rows, 0, self::EXPORT_LIMIT));

        header('Content-Type: text/csv; charset=utf-8');
        header('Cache-Control: no-store');

        if ($truncated) {
            header('X-Export-Truncated: true');
            header('Content-Disposition: attachment; filename="dmarc-report-search-truncated.csv"');
        } else {
            header('Content-Disposition: attachment; filename="dmarc-report-search.csv"');
        }

        echo $csv;
    }

    /**
     * @param list<array{domain: string, source_ip: string, rdns: ?string, asn_org: ?string, label: string, volume: int, dkim_result: string, spf_result: string, disposition: string, date_begin: string, date_end: string, report_id: string}> $rows
     */
    private function render(
        AuthUser $user,
        ?ReportSearchCriteria $criteria,
        array $rows,
        ?string $error = null,
        ?string $notice = null,
        ?string $limitNotice = null,
    ): void {
        $domains = $this->reports->domains();
        $labels  = array_values(array_unique(array_merge(['known', 'unknown', 'pending'], $this->reports->labels())));
        $query   = $_GET;

        $domainValue   = $query['domain'] ?? (Roles::atLeast($user->role, Roles::ADMIN) ? 'all' : '');
        $domainValue   = \is_string($domainValue) ? $domainValue : '';
        $domainOptions = '';

        if (Roles::atLeast($user->role, Roles::ADMIN)) {
            $domainOptions .= '<option value="all">All domains</option>';
        } else {
            $domainOptions .= '<option value="">Choose a domain</option>';
        }

        foreach ($domains as $domain) {
            $id = (string) $domain['id'];
            $domainOptions .= '<option value="' . $id . '">'
                . View::e($domain['domain']) . '</option>';
        }

        $rangeValue   = $query['range'] ?? '30';
        $rangeValue   = \is_string($rangeValue) ? $rangeValue : '30';
        $rangeOptions = '';

        foreach (['7' => 'Last 7 days', '30' => 'Last 30 days', '90' => 'Last 90 days', 'custom' => 'Custom range'] as $value => $text) {
            $rangeOptions .= '<option value="' . $value . '">' . $text . '</option>';
        }

        $fromValue = $criteria !== null ? $criteria->fromDate : $this->safeQueryString('from');
        $toValue   = $criteria !== null ? $criteria->throughDate : $this->safeQueryString('to');
        $filters   = '<div class="report-search-grid">'
            . $this->selectField('Domain', 'domain', $domainOptions, $domainValue)
            . $this->selectField('Report period start', 'range', $rangeOptions, $rangeValue)
            . $this->inputField('From', 'from', $fromValue, 'date')
            . $this->inputField('Through', 'to', $toValue, 'date')
            . $this->selectField('Sender label', 'label', $this->options($labels, 'Any label'), $this->safeQueryString('label'))
            . $this->selectField('DKIM result', 'dkim', $this->options(['pass', 'fail'], 'Any'), $this->safeQueryString('dkim'))
            . $this->selectField('SPF result', 'spf', $this->options(['pass', 'fail'], 'Any'), $this->safeQueryString('spf'))
            . $this->selectField('Disposition', 'disposition', $this->options(['none', 'quarantine', 'reject'], 'Any'), $this->safeQueryString('disposition'))
            . $this->inputField('ASN organization contains', 'asn_org', $this->safeQueryString('asn_org'), 'text')
            . '</div><div class="form-actions"><button class="btn btn-primary" type="submit">Search</button></div>';

        $body = '<div class="page-head"><div><h1>Report search' . View::helpTooltip('page-report-search', 'How report search works') . '</h1>'
            . '<div class="sub">Filter aggregate report records by report-period start date, sender label, authentication result, disposition, and ASN organization.</div></div></div>';

        if ($error !== null) {
            $body .= '<p class="error">' . View::e($error) . '</p>';
        }

        if ($notice !== null) {
            $body .= '<p class="card-sub">' . View::e($notice) . '</p>';
        }

        $body .= '<form method="get" action="/reports" class="card report-search-form">' . $filters . '</form>';

        if ($criteria !== null && ($criteria->domainId !== null || Roles::atLeast($user->role, Roles::ADMIN))) {
            $params      = array_filter($query, static fn (mixed $value): bool => \is_string($value) && $value !== '');
            $downloadUrl = '/reports/export?' . http_build_query($params);
            $body .= '<div class="section-head"><h2>Matching report records</h2>'
                . '<a class="btn btn-secondary btn-sm" href="' . View::e($downloadUrl) . '">Download CSV (max 10,000)</a></div>';

            if ($limitNotice !== null) {
                $body .= '<p class="card-sub">' . View::e($limitNotice) . '</p>';
            }

            $body .= $this->renderRows($rows);
        }

        View::render('Report search', $body, $user);
    }

    /** @param list<string> $values */
    private function options(array $values, string $firstLabel): string
    {
        $html = '<option value="">' . View::e($firstLabel) . '</option>';

        foreach ($values as $value) {
            $html .= '<option value="' . View::e($value) . '">' . View::e($value) . '</option>';
        }

        return $html;
    }

    private function selectField(string $label, string $name, string $options, string $selected): string
    {
        if ($selected !== '') {
            $options = preg_replace(
                '/(<option value="' . preg_quote(View::e($selected), '/') . '")/',
                '$1 selected',
                $options,
                1
            ) ?? $options;
        }

        return '<label class="form-field">' . View::e($label)
            . '<select name="' . View::e($name) . '">' . $options . '</select></label>';
    }

    private function inputField(string $label, string $name, string $value, string $type): string
    {
        return '<label class="form-field">' . View::e($label)
            . '<input type="' . View::e($type) . '" name="' . View::e($name) . '" value="' . View::e($value) . '"></label>';
    }

    /**
     * @param list<array{domain: string, source_ip: string, rdns: ?string, asn_org: ?string, label: string, volume: int, dkim_result: string, spf_result: string, disposition: string, date_begin: string, date_end: string, report_id: string}> $rows
     */
    private function renderRows(array $rows): string
    {
        if ($rows === []) {
            return '<div class="table-card"><p class="empty">No report records matched these filters.</p></div>';
        }

        $html = '<div class="table-card"><div class="table-scroll"><table><thead><tr>'
            . '<th>Domain</th><th>Source IP</th><th>rDNS</th><th>ASN org</th><th>Label</th><th>Volume</th>'
            . '<th>DKIM</th><th>SPF</th><th>Disposition</th><th>Report period</th><th>Report ID</th>'
            . '</tr></thead><tbody>';

        foreach ($rows as $row) {
            $html .= '<tr><td>' . View::e($row['domain']) . '</td>'
                . '<td class="mono">' . View::e($row['source_ip']) . '</td>'
                . '<td>' . View::e($row['rdns'] ?? '—') . '</td>'
                . '<td>' . View::e($row['asn_org'] ?? '—') . '</td>'
                . '<td>' . View::e($row['label']) . '</td>'
                . '<td class="num">' . $row['volume'] . '</td>'
                . '<td>' . View::e($row['dkim_result']) . '</td>'
                . '<td>' . View::e($row['spf_result']) . '</td>'
                . '<td>' . View::e($row['disposition']) . '</td>'
                . '<td class="mono">' . View::e($row['date_begin']) . ' – ' . View::e($row['date_end']) . '</td>'
                . '<td>' . View::e($row['report_id']) . '</td></tr>';
        }

        return $html . '</tbody></table></div></div>';
    }

    private function safeQueryString(string $key): string
    {
        return isset($_GET[$key]) && \is_string($_GET[$key]) ? $_GET[$key] : '';
    }
}
