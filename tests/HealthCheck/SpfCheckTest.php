<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck;

use App\HealthCheck\Checks\SpfCheck;
use App\HealthCheck\HealthCheckItemResult;
use PHPUnit\Framework\TestCase;

final class SpfCheckTest extends TestCase
{
    public function testNoRecordFails(): void
    {
        $check  = new SpfCheck(new FakeDnsResolver());
        $result = $check->run('example.com');

        self::assertSame(HealthCheckItemResult::FAIL, $result[0]->status);
    }

    public function testMultipleRecordsFails(): void
    {
        $dns    = new FakeDnsResolver(['example.com' => ['v=spf1 -all', 'v=spf1 ~all']]);
        $result = (new SpfCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::FAIL, $result[0]->status);
        self::assertStringContainsString('multiple', $result[0]->detail['reason']);
    }

    public function testDangerousPlusAllFails(): void
    {
        $dns    = new FakeDnsResolver(['example.com' => ['v=spf1 include:_spf.google.com +all']]);
        $result = (new SpfCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::FAIL, $result[0]->status);
    }

    public function testWeakTildeAllWarns(): void
    {
        $dns    = new FakeDnsResolver(['example.com' => ['v=spf1 include:_spf.google.com ~all']]);
        $result = (new SpfCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::WARN, $result[0]->status);
    }

    public function testStrictMinusAllPasses(): void
    {
        $dns    = new FakeDnsResolver(['example.com' => ['v=spf1 include:_spf.google.com -all']]);
        $result = (new SpfCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::PASS, $result[0]->status);
    }

    public function testMissingAllMechanismWarns(): void
    {
        $dns    = new FakeDnsResolver(['example.com' => ['v=spf1 include:_spf.google.com']]);
        $result = (new SpfCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::WARN, $result[0]->status);
    }

    public function testExceedingLookupLimitFails(): void
    {
        $includes = implode(' ', array_map(static fn (int $i): string => "include:domain$i.com", range(1, 11)));
        $dns      = new FakeDnsResolver(['example.com' => ["v=spf1 $includes -all"]]);
        $result   = (new SpfCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::FAIL, $result[0]->status);
        self::assertSame(11, $result[0]->detail['lookup_count']);
    }
}
