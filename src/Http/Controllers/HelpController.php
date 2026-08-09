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
            . '<div class="sub">DMARC 101 — explanations for every term, finding, and recommendation this tool surfaces.</div></div></div>';

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
