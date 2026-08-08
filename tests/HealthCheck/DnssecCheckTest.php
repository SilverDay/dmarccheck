<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck;

use App\HealthCheck\Checks\DnssecCheck;
use App\HealthCheck\HealthCheckItemResult;
use PHPUnit\Framework\TestCase;

final class DnssecCheckTest extends TestCase
{
    public function testDsRecordPresentPasses(): void
    {
        $dig    = new FakeDigLookup(['example.com:DS' => ['2371 13 2 ABCD']]);
        $result = (new DnssecCheck($dig))->run('example.com');

        self::assertSame(HealthCheckItemResult::PASS, $result[0]->status);
    }

    public function testNoDsRecordIsInformational(): void
    {
        $dig    = new FakeDigLookup(['example.com:DS' => []]);
        $result = (new DnssecCheck($dig))->run('example.com');

        self::assertSame(HealthCheckItemResult::INFO, $result[0]->status);
    }

    public function testQueryFailureIsError(): void
    {
        $dig    = new FakeDigLookup(['example.com:DS' => null]);
        $result = (new DnssecCheck($dig))->run('example.com');

        self::assertSame(HealthCheckItemResult::ERROR, $result[0]->status);
    }
}
