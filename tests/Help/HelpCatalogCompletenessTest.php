<?php

declare(strict_types=1);

namespace App\Tests\Help;

use App\HealthCheck\HealthCheckItemResult;
use App\Help\HelpRepository;
use PHPUnit\Framework\TestCase;

/**
 * Ties the shipped catalog to the actual code it documents, so a future
 * R13 or a new health-check status silently missing help content fails
 * here instead of shipping a dead tooltip.
 */
final class HelpCatalogCompletenessTest extends TestCase
{
    private HelpRepository $repo;

    protected function setUp(): void
    {
        $this->repo = new HelpRepository(HelpRepository::defaultContentFiles());
    }

    public function testEveryRecommendationRuleHasAnArticle(): void
    {
        for ($i = 1; $i <= 12; $i++) {
            self::assertNotNull($this->repo->get("rule-r{$i}"), "Missing help article for rule R{$i}");
        }
    }

    public function testEveryHealthCheckStatusHasAnArticle(): void
    {
        foreach ([
            HealthCheckItemResult::PASS,
            HealthCheckItemResult::WARN,
            HealthCheckItemResult::FAIL,
            HealthCheckItemResult::ERROR,
            HealthCheckItemResult::INFO,
        ] as $status) {
            self::assertNotNull($this->repo->get("hc-status-{$status}"), "Missing help article for health-check status \"{$status}\"");
        }
    }

    public function testEveryAlertTypeHasAnArticle(): void
    {
        foreach (['heartbeat', 'policy-drift', 'unknown-volume', 'pass-rate'] as $alert) {
            self::assertNotNull($this->repo->get("alert-{$alert}"), "Missing help article for alert \"{$alert}\"");
        }
    }

    /** Every page-head View::helpTooltip() call site needs a matching article. */
    public function testEveryPageGuideReferencedFromAControllerHasAnArticle(): void
    {
        foreach ([
            'page-domains',
            'page-domain-detail',
            'page-report-detail',
            'page-allowlist',
            'page-users',
            'page-audit-log',
            'page-security',
        ] as $page) {
            self::assertNotNull($this->repo->get($page), "Missing help article for \"{$page}\"");
        }
    }
}
