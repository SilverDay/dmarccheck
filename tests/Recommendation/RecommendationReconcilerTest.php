<?php

declare(strict_types=1);

namespace App\Tests\Recommendation;

use App\Recommendation\ExistingRecommendation;
use App\Recommendation\RecommendationReconciler;
use App\Recommendation\RuleFinding;
use PHPUnit\Framework\TestCase;

final class RecommendationReconcilerTest extends TestCase
{
    public function testNewFindingWithNoExistingRowIsInserted(): void
    {
        $finding = new RuleFinding('R1', 'low', '203.0.113.5', []);
        $plan    = (new RecommendationReconciler())->plan([$finding], [], []);

        self::assertSame([$finding], $plan->toInsert);
        self::assertSame([], $plan->toTouch);
        self::assertSame([], $plan->toResolve);
    }

    public function testMatchingSubjectAndRuleIsTouchedNotDuplicated(): void
    {
        $finding  = new RuleFinding('R1', 'low', '203.0.113.5', ['spf_fail_count' => 9]);
        $existing = [new ExistingRecommendation(42, 'R1', '203.0.113.5')];

        $plan = (new RecommendationReconciler())->plan([$finding], $existing, []);

        self::assertSame([], $plan->toInsert);
        self::assertCount(1, $plan->toTouch);
        self::assertSame(42, $plan->toTouch[0]['id']);
        self::assertSame($finding, $plan->toTouch[0]['finding']);
        self::assertSame([], $plan->toResolve);
    }

    public function testExistingRowWithNoMatchingFindingIsResolved(): void
    {
        $existing = [new ExistingRecommendation(7, 'R1', '203.0.113.5')];
        $plan     = (new RecommendationReconciler())->plan([], $existing, []);

        self::assertSame([], $plan->toInsert);
        self::assertSame([], $plan->toTouch);
        self::assertSame([7], $plan->toResolve);
    }

    public function testDomainWideRuleMatchesOnNullSubject(): void
    {
        $finding  = new RuleFinding('R9', 'high', null, []);
        $existing = [new ExistingRecommendation(3, 'R9', null)];

        $plan = (new RecommendationReconciler())->plan([$finding], $existing, []);

        self::assertSame([], $plan->toInsert);
        self::assertCount(1, $plan->toTouch);
        self::assertSame([], $plan->toResolve);
    }

    public function testSuppressedSubjectIsNeitherInsertedNorCountedAsExisting(): void
    {
        $finding = new RuleFinding('R1', 'low', '203.0.113.5', []);
        $plan    = (new RecommendationReconciler())->plan([$finding], [], ['R1' => ['203.0.113.5']]);

        self::assertSame([], $plan->toInsert);
        self::assertSame([], $plan->toTouch);
        self::assertSame([], $plan->toResolve);
    }

    public function testDifferentSubjectsForSameRuleAreIndependent(): void
    {
        $findingA = new RuleFinding('R5', 'high', '203.0.113.5', []);
        $findingB = new RuleFinding('R5', 'high', '198.51.100.9', []);
        $existing = [new ExistingRecommendation(1, 'R5', '203.0.113.5')];

        $plan = (new RecommendationReconciler())->plan([$findingA, $findingB], $existing, []);

        self::assertSame([$findingB], $plan->toInsert);
        self::assertCount(1, $plan->toTouch);
        self::assertSame([], $plan->toResolve);
    }
}
