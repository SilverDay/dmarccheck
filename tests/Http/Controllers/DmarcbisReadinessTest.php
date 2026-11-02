<?php

declare(strict_types=1);

namespace App\Tests\Http\Controllers;

use App\HealthCheck\HealthCheckItemResult;
use App\HealthCheck\HealthCheckSummary;
use App\Http\Controllers\DomainController;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;

final class DmarcbisReadinessTest extends TestCase
{
    public function testOwnPolicyShowsDeprecatedTagsAndOptionalCurrentTags(): void
    {
        $html = $this->render('warn', [
            'policy_string'                 => 'v=DMARC1; p=none; pct=50; rf=afrf; ri=86400',
            'policy'                        => 'none',
            'pct'                           => 50,
            'rf'                            => 'afrf',
            'ri'                            => '86400',
            'non_existent_subdomain_policy' => 'reject',
            'psd'                           => 'n',
            'testing'                       => 'n',
        ]);

        self::assertStringContainsString('DMARCbis readiness', $html);
        self::assertStringContainsString('Still published (pct=50)', $html);
        self::assertStringContainsString('rf=afrf, ri=86400', $html);
        self::assertStringContainsString('Publishes its own record directly', $html);
        self::assertStringContainsString('np=reject, psd=n, t=n', $html);
        self::assertStringContainsString('dmarcbis-deprecated-tags', $html);
    }

    public function testPartialEnforcementPercentageWarnsAgainstAutomaticRemoval(): void
    {
        $html = $this->render('warn', [
            'policy_string' => 'v=DMARC1; p=quarantine; pct=50',
            'policy'        => 'quarantine',
            'pct'           => 50,
        ]);

        self::assertStringContainsString('removing it may increase enforcement', $html);
        self::assertStringNotContainsString('Use the &quot;Fix me&quot; button', $html);
    }

    public function testInvalidDmarcbisTagsAreShownAsWarnings(): void
    {
        $html = $this->render('warn', [
            'policy_string'                 => 'v=DMARC1; p=reject; np=full; psd=u; t=maybe',
            'non_existent_subdomain_policy' => 'full',
            'psd'                           => 'u',
            'testing'                       => 'maybe',
            'invalid_dmarcbis_tags'         => ['np' => 'full', 'psd' => 'u', 't' => 'maybe'],
        ]);

        self::assertStringContainsString('badge warning', $html);
        self::assertStringContainsString('Invalid value(s): np=full, psd=u, t=maybe', $html);
    }

    public function testInheritedPolicyIsShownAsCoverageWithoutOwnRecord(): void
    {
        $html = $this->render('pass', [
            'org_domain'               => 'example.com',
            'org_domain_policy_string' => 'v=DMARC1; p=reject',
        ]);

        self::assertStringContainsString('Inherits from example.com', $html);
        self::assertStringContainsString('badge neutral', $html);
    }

    public function testUncoveredDomainAndUnknownCheckRemainDistinct(): void
    {
        $uncovered = $this->render('fail', ['reason' => 'no DMARC record found in the tree walk']);
        $unknown   = $this->render('error', ['reason' => 'DNS lookup timed out']);

        self::assertStringContainsString('No coverage found anywhere', $uncovered);
        self::assertStringContainsString('badge danger', $uncovered);
        self::assertStringContainsString('Could not determine whether this tag is published', $unknown);
        self::assertStringContainsString('badge neutral', $unknown);
    }

    private function render(string $status, array $detail): string
    {
        $controller = (new ReflectionClass(DomainController::class))->newInstanceWithoutConstructor();
        $method     = new ReflectionMethod(DomainController::class, 'renderDmarcbisReadiness');
        $method->setAccessible(true);

        /** @var string $html */
        $html = $method->invoke(
            $controller,
            new HealthCheckSummary('2026-01-01 00:00:00', 'manual', [
                new HealthCheckItemResult('dns', 'dmarc', $status, $detail),
            ])
        );

        return $html;
    }
}
