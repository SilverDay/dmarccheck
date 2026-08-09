<?php

declare(strict_types=1);

namespace App\Help;

/**
 * Loads every content/*.php file's returned list<HelpArticle> into a
 * slug => HelpArticle map at construction — pure/in-memory, no PDO, so
 * it's directly unit-testable (unlike the PDO-orchestrating repositories
 * elsewhere in this codebase). A duplicate slug across two content files
 * throws rather than silently overwriting, since that would mean one
 * article shadows another with no way to notice from the UI.
 */
final class HelpRepository
{
    /** @var array<string, HelpArticle> */
    private array $bySlug = [];

    /** @param list<string> $contentFiles absolute paths, each returning list<HelpArticle> */
    public function __construct(array $contentFiles)
    {
        foreach ($contentFiles as $file) {
            /** @var list<HelpArticle> $articles */
            $articles = require $file;

            foreach ($articles as $article) {
                if (isset($this->bySlug[$article->slug])) {
                    throw new \LogicException("Duplicate help slug \"{$article->slug}\" in {$file}");
                }

                $this->bySlug[$article->slug] = $article;
            }
        }
    }

    /** @return list<string> absolute paths to every shipped content file, in catalog order */
    public static function defaultContentFiles(): array
    {
        $dir = __DIR__ . '/content/';

        return [
            $dir . 'dmarc.php',
            $dir . 'spf.php',
            $dir . 'dkim.php',
            $dir . 'healthcheck.php',
            $dir . 'rules.php',
            $dir . 'alerting.php',
            $dir . 'policy.php',
            $dir . 'general.php',
            $dir . 'pages.php',
        ];
    }

    public function get(string $slug): ?HelpArticle
    {
        return $this->bySlug[$slug] ?? null;
    }

    /** @return list<HelpArticle> */
    public function all(): array
    {
        return array_values($this->bySlug);
    }

    /** @return array<string, list<HelpArticle>> category => articles, insertion order preserved within each category */
    public function byCategory(): array
    {
        $grouped = [];

        foreach ($this->bySlug as $article) {
            $grouped[$article->category][] = $article;
        }

        return $grouped;
    }
}
