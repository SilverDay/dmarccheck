<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Auth\AuthUser;
use App\Help\HelpArticle;
use App\Help\HelpRepository;
use App\Http\AuthMiddleware;
use App\Http\View;

/**
 * "DMARC 101" help system (docs/feature-helpsystem.md). index()/show() are
 * public — no tenant data ever appears here, and a shareable article link
 * shouldn't require login — while inline() (the tooltip JSON fetch) is
 * dashboard-only UI and stays behind auth like the rest of the app.
 * Router (src/Http/Router.php) is exact-string-match only, so articles are
 * addressed by query string (?slug=) rather than a path param, same as
 * DomainController's /domain?domain=.
 */
final class HelpController
{
    public function __construct(
        private readonly HelpRepository $help,
        private readonly AuthMiddleware $auth,
    ) {
    }

    public function index(): void
    {
        $user = $this->auth->currentUser();
        $body = '<div class="page-head"><div><h1>Help</h1>'
            . '<div class="sub">DMARC 101 — explanations for every term, finding, and recommendation this tool surfaces.</div></div></div>'
            . $this->searchForm();

        foreach ($this->help->byCategory() as $category => $articles) {
            $items = '';

            foreach ($articles as $article) {
                $items .= '<div class="list-row"><div class="meta"><div>'
                    . '<div class="name"><a href="' . View::e($this->articleUrl($article->slug)) . '">' . View::e($article->title) . '</a></div>'
                    . '<div class="detail">' . View::e($article->summary) . '</div>'
                    . '</div></div></div>';
            }

            $body .= '<div class="section-head"><h2>' . View::e($category) . '</h2></div>'
                . '<div class="table-card help-index-card">' . $items . '</div>';
        }

        View::render('Help', $body, $user);
    }

    public function search(): void
    {
        $user        = $this->auth->currentUser();
        $rawQuery    = $_GET['q'] ?? '';
        $invalidType = !\is_string($rawQuery);
        $query       = $invalidType ? '' : trim($rawQuery);
        $body        = '<div class="page-head"><div><h1>Search help</h1>'
            . '<div class="sub"><a href="/help">&larr; Browse all help articles</a></div></div></div>'
            . $this->searchForm($query);

        if ($invalidType) {
            http_response_code(400);
            $body .= '<p class="error">Search query must be a single text value.</p>';
        } elseif ($query === '') {
            $body .= '<p class="card-sub">Enter a word or phrase to search article titles and summaries.</p>';
        } elseif (mb_strlen($query) > 120) {
            http_response_code(400);
            $body .= '<p class="error">Search terms must be 120 characters or fewer.</p>';
        } else {
            $articles = $this->help->search($query);

            if ($articles === []) {
                $body .= '<p class="card-sub">No help articles matched “' . View::e($query) . '”.</p>';
            } else {
                $items = '';

                foreach ($articles as $article) {
                    $items .= '<div class="list-row"><div class="meta"><div>'
                        . '<div class="name"><a href="' . View::e($this->articleUrl($article->slug)) . '">' . View::e($article->title) . '</a></div>'
                        . '<div class="detail">' . View::e($article->summary) . '</div>'
                        . '</div></div></div>';
                }

                $body .= '<div class="table-card help-index-card">' . $items . '</div>';
            }
        }

        View::render('Search help', $body, $user);
    }

    public function show(): void
    {
        $user    = $this->auth->currentUser();
        $slug    = (string) ($_GET['slug'] ?? '');
        $article = $this->help->get($slug);

        if ($article === null) {
            http_response_code(404);
            $body = '<div class="page-head"><div><h1>Not found</h1>'
                . '<div class="sub">No help article matches that link. <a href="/help">Browse all help articles</a>.</div></div></div>';
            View::render('Not found', $body, $user);

            return;
        }

        $body = '<div class="page-head"><div><h1>' . View::e($article->title) . '</h1>'
            . '<div class="sub"><a href="/help">&larr; All help articles</a> &middot; ' . View::e($article->category) . '</div></div></div>'
            . '<div class="card">' . $article->body . '</div>'
            . $this->renderReferences($article);

        View::render($article->title, $body, $user);
    }

    public function inline(AuthUser $user): void
    {
        $slug    = (string) ($_GET['slug'] ?? '');
        $article = $this->help->get($slug);

        header('Content-Type: application/json');

        if ($article === null) {
            http_response_code(404);
            echo json_encode(['error' => 'Unknown help slug.'], JSON_THROW_ON_ERROR);

            return;
        }

        echo json_encode([
            'summary' => $article->summary,
            'moreUrl' => $this->articleUrl($article->slug),
        ], JSON_THROW_ON_ERROR);
    }

    public function context(AuthUser $user): void
    {
        $rawPath = $_GET['path'] ?? '';
        $path    = \is_string($rawPath) ? $rawPath : '';
        $slugs   = match (true) {
            $path === '/' => [
                'page-domains',
                'dmarc-overview',
                'card-pass-fail-chart',
                'known-vs-unknown',
            ],
            $path === '/domain' => [
                'page-domain-detail',
                'card-policy',
                'policy-current-published',
                'policy-approved-baseline',
                'policy-target',
                'card-pass-fail-chart',
                'card-health-check',
                'hc-status-pass',
                'hc-status-warn',
                'hc-status-fail',
                'hc-status-error',
                'hc-status-info',
                'hc-mx',
                'hc-dnssec',
                'hc-mta-sts',
                'hc-tls-rpt',
                'hc-bimi',
                'hc-starttls',
                'hc-dnsbl',
                'hc-rhsbl',
                'hc-fcrdns',
                'hc-report-auth',
                'card-sources',
                'card-recommendations',
                'card-recent-reports',
                'rule-r1',
                'rule-r2',
                'rule-r3',
                'rule-r4',
                'rule-r5',
                'rule-r6',
                'rule-r7',
                'rule-r8',
                'rule-r9',
                'rule-r10',
                'rule-r11',
                'rule-r12',
            ],
            $path === '/domain/report' => [
                'page-report-detail',
                'dmarc-aggregate-reports',
                'dkim-overview',
                'spf-overview',
            ],
            $path === '/admin/known-senders'    => ['page-allowlist', 'known-senders-allowlist'],
            $path === '/admin/users'            => ['page-users', 'page-security'],
            $path === '/admin/audit-log'        => ['page-audit-log'],
            str_starts_with($path, '/account/') => ['page-security'],
            default                             => ['dmarc-overview', 'spf-overview', 'dkim-overview'],
        };
        $articles = [];

        foreach ($slugs as $slug) {
            $article = $this->help->get($slug);

            if ($article === null) {
                throw new \LogicException("Contextual help references unknown article \"{$slug}\"");
            }

            $articles[] = [
                'title'   => $article->title,
                'summary' => $article->summary,
                'url'     => $this->articleUrl($article->slug),
            ];
        }

        header('Content-Type: application/json');
        echo json_encode(['articles' => $articles], JSON_THROW_ON_ERROR);
    }

    private function searchForm(string $query = ''): string
    {
        return '<form method="get" action="/help/search" class="help-search-form">'
            . '<label for="help-search-query">Search article titles and summaries</label>'
            . '<div><input id="help-search-query" name="q" type="search" value="' . View::e($query) . '" maxlength="120">'
            . '<button type="submit" class="btn btn-primary">Search</button></div>'
            . '</form>';
    }

    private function renderReferences(HelpArticle $article): string
    {
        if ($article->references === []) {
            return '';
        }

        $items = '';

        foreach ($article->references as $reference) {
            $items .= '<li>' . View::e($reference) . '</li>';
        }

        return '<div class="card-sub mt-md">References<ul>' . $items . '</ul></div>';
    }

    private function articleUrl(string $slug): string
    {
        return '/help/article?' . http_build_query(['slug' => $slug]);
    }
}
