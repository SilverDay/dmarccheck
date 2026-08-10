<?php

declare(strict_types=1);

namespace App\Tests\Help;

use App\Help\HelpRepository;
use PHPUnit\Framework\TestCase;

final class HelpRepositoryTest extends TestCase
{
    public function testTheShippedCatalogHasNoDuplicateSlugsAcrossFiles(): void
    {
        $repo = new HelpRepository(HelpRepository::defaultContentFiles());

        self::assertCount(90, $repo->all());
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
