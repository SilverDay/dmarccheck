<?php

declare(strict_types=1);

namespace App\Tests\Help;

use App\Help\HelpArticle;
use App\Help\HelpRepository;
use PHPUnit\Framework\TestCase;

final class HelpRepositoryTest extends TestCase
{
    public function testTheShippedCatalogHasNoDuplicateSlugsAcrossFiles(): void
    {
        $repo = new HelpRepository(HelpRepository::defaultContentFiles());

        self::assertCount(92, $repo->all());
    }

    public function testGetResolvesAKnownSlug(): void
    {
        $repo = new HelpRepository(HelpRepository::defaultContentFiles());

        self::assertSame('dmarc-overview', $repo->get('dmarc-overview')?->slug);
    }

    public function testGetReturnsNullForAnUnknownSlug(): void
    {
        $repo = new HelpRepository(HelpRepository::defaultContentFiles());

        self::assertNull($repo->get('does-not-exist'));
    }

    public function testSearchMatchesTitlesAndSummariesWithoutCaseSensitivity(): void
    {
        $repo = new HelpRepository(HelpRepository::defaultContentFiles());

        self::assertContains('dmarc-overview', array_map(
            static fn (HelpArticle $article): string => $article->slug,
            $repo->search('  DMARC  '),
        ));
        self::assertContains('known-vs-unknown', array_map(
            static fn (HelpArticle $article): string => $article->slug,
            $repo->search('source IP'),
        ));
    }

    public function testSearchReturnsNoResultsForEmptyOrUnmatchedQueries(): void
    {
        $repo = new HelpRepository(HelpRepository::defaultContentFiles());

        self::assertSame([], $repo->search('   '));
        self::assertSame([], $repo->search('no article should contain this phrase'));
    }

    public function testByCategoryGroupsArticlesUnderTheirOwnCategory(): void
    {
        $repo    = new HelpRepository(HelpRepository::defaultContentFiles());
        $grouped = $repo->byCategory();

        self::assertArrayHasKey('DMARC fundamentals', $grouped);

        foreach ($grouped['DMARC fundamentals'] as $article) {
            self::assertSame('DMARC fundamentals', $article->category);
        }
    }

    public function testADuplicateSlugAcrossContentFilesThrows(): void
    {
        $this->expectException(\LogicException::class);

        new HelpRepository([
            __DIR__ . '/fixtures/dup-a.php',
            __DIR__ . '/fixtures/dup-b.php',
        ]);
    }
}
