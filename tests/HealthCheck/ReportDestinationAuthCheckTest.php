<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck;

use App\HealthCheck\Checks\ReportDestinationAuthCheck;
use App\HealthCheck\HealthCheckItemResult;
use PHPUnit\Framework\TestCase;

final class ReportDestinationAuthCheckTest extends TestCase
{
    public function testNoDmarcRecordIsInformational(): void
    {
        $result = (new ReportDestinationAuthCheck(new FakeDnsResolver()))->run('example.com');

        self::assertSame(HealthCheckItemResult::INFO, $result[0]->status);
    }

    public function testSameDomainRuaNeedsNoAuthorization(): void
    {
        $dns = new FakeDnsResolver([
            '_dmarc.example.com' => ['v=DMARC1; p=reject; rua=mailto:reports@example.com'],
        ]);
        $result = (new ReportDestinationAuthCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::INFO, $result[0]->status);
        self::assertStringContainsString('no cross-domain', $result[0]->detail['reason']);
    }

    public function testCrossDomainWithAuthorizationRecordPasses(): void
    {
        $dns = new FakeDnsResolver([
            '_dmarc.roya.at'                      => ['v=DMARC1; p=reject; rua=mailto:reports@silverday.de'],
            'roya.at._report._dmarc.silverday.de' => ['v=DMARC1'],
        ]);
        $result = (new ReportDestinationAuthCheck($dns))->run('roya.at');

        self::assertSame(HealthCheckItemResult::PASS, $result[0]->status);
        self::assertSame('silverday.de', $result[0]->detail['destination_domain']);
    }

    public function testCrossDomainWithoutAuthorizationRecordFails(): void
    {
        $dns = new FakeDnsResolver([
            '_dmarc.roya.at' => ['v=DMARC1; p=reject; rua=mailto:reports@silverday.de'],
        ]);
        $result = (new ReportDestinationAuthCheck($dns))->run('roya.at');

        self::assertSame(HealthCheckItemResult::FAIL, $result[0]->status);
    }
}
