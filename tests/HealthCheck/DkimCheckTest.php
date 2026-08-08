<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck;

use App\HealthCheck\Checks\DkimCheck;
use App\HealthCheck\HealthCheckItemResult;
use PHPUnit\Framework\TestCase;

final class DkimCheckTest extends TestCase
{
    public function testNoSelectorsResolveReturnsInfoNotFail(): void
    {
        $check  = new DkimCheck(new FakeDnsResolver(), ['default', 'google']);
        $result = $check->run('example.com');

        self::assertCount(1, $result);
        self::assertSame(HealthCheckItemResult::INFO, $result[0]->status);
        self::assertStringContainsString('not enumerable', $result[0]->detail['reason']);
    }

    public function testValidKeyPasses(): void
    {
        $dns    = new FakeDnsResolver(['default._domainkey.example.com' => ['v=DKIM1; k=rsa; p=MIGfMA0GCSq...']]);
        $result = (new DkimCheck($dns, ['default']))->run('example.com');

        self::assertSame(HealthCheckItemResult::PASS, $result[0]->status);
        self::assertSame('default', $result[0]->detail['selector']);
    }

    public function testEmptyPTagFails(): void
    {
        $dns    = new FakeDnsResolver(['default._domainkey.example.com' => ['v=DKIM1; k=rsa; p=']]);
        $result = (new DkimCheck($dns, ['default']))->run('example.com');

        self::assertSame(HealthCheckItemResult::FAIL, $result[0]->status);
    }

    public function testRecordWithoutPTagWarns(): void
    {
        $dns    = new FakeDnsResolver(['default._domainkey.example.com' => ['v=DKIM1; k=rsa']]);
        $result = (new DkimCheck($dns, ['default']))->run('example.com');

        self::assertSame(HealthCheckItemResult::WARN, $result[0]->status);
    }

    public function testOnlyMatchingSelectorsAreReported(): void
    {
        $dns    = new FakeDnsResolver(['default._domainkey.example.com' => ['v=DKIM1; p=abc']]);
        $result = (new DkimCheck($dns, ['default', 'nonexistent']))->run('example.com');

        self::assertCount(1, $result);
        self::assertSame('default', $result[0]->detail['selector']);
    }
}
