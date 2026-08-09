<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck\Fix;

use App\HealthCheck\Fix\TlsRptFixSuggester;
use PHPUnit\Framework\TestCase;

final class TlsRptFixSuggesterTest extends TestCase
{
    public function testNoRecordSuggestsOne(): void
    {
        $fixes = TlsRptFixSuggester::suggest('example.com', ['reason' => 'no TLS-RPT record published'], 'dmarc@example.com');

        self::assertCount(1, $fixes);
        self::assertSame('_smtp._tls.example.com', $fixes[0]->recordName);
        self::assertSame('v=TLSRPTv1; rua=mailto:dmarc@example.com', $fixes[0]->recordValue);
    }

    public function testRecordAlreadyPresentHasNoSuggestion(): void
    {
        $fixes = TlsRptFixSuggester::suggest('example.com', ['reason' => 'TLS-RPT record present'], 'dmarc@example.com');

        self::assertSame([], $fixes);
    }
}
