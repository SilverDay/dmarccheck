<?php

declare(strict_types=1);

namespace App\Help;

/**
 * One "DMARC 101" help entry (spec proposal docs/feature-helpsystem.md
 * §5/§6.1). `summary` is what the inline tooltip endpoint returns;
 * `body` is the full-article HTML shown at /help/article — authored
 * content, not user input, so it's trusted HTML rather than escaped.
 */
final readonly class HelpArticle
{
    /** @param list<string> $references */
    public function __construct(
        public string $slug,
        public string $title,
        public string $category,
        public string $summary,
        public string $body,
        public array $references = [],
    ) {
    }
}
