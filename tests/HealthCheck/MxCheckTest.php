<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck;

use App\HealthCheck\Checks\MxCheck;
use App\HealthCheck\HealthCheckItemResult;
use App\HealthCheck\MxRecord;
use PHPUnit\Framework\TestCase;

final class MxCheckTest extends TestCase
{
    public function testNoMxRecordsFails(): void
    {
        $result = (new MxCheck(new FakeDnsResolver()))->run('example.com');

        self::assertCount(1, $result);
        self::assertSame(HealthCheckItemResult::FAIL, $result[0]->status);
    }

    public function testResolvingMxPasses(): void
    {
        $dns = new FakeDnsResolver(
            mxRecords: ['example.com' => [new MxRecord(10, 'mail.example.com')]],
            aRecords: ['mail.example.com' => ['203.0.113.5']],
        );
        $result = (new MxCheck($dns))->run('example.com');

        self::assertCount(2, $result);
        self::assertSame(HealthCheckItemResult::PASS, $result[0]->status);
        self::assertSame(HealthCheckItemResult::PASS, $result[1]->status);
    }

    public function testMxHostNotResolvingFails(): void
    {
        $dns    = new FakeDnsResolver(mxRecords: ['example.com' => [new MxRecord(10, 'mail.example.com')]]);
        $result = (new MxCheck($dns))->run('example.com');

        self::assertSame(HealthCheckItemResult::FAIL, $result[1]->status);
    }
}
