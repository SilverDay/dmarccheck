<?php

declare(strict_types=1);

namespace App\Tests\HealthCheck\Fix;

use App\HealthCheck\Fix\MtaStsFixSuggester;
use PHPUnit\Framework\TestCase;

final class MtaStsFixSuggesterTest extends TestCase
{
    public function testNoRecordSuggestsBothTheDnsRecordAndThePolicyFile(): void
    {
        $fixes = MtaStsFixSuggester::suggest('example.com', ['reason' => 'no MTA-STS record published'], []);

        self::assertCount(2, $fixes);
        self::assertSame('_mta-sts.example.com', $fixes[0]->recordName);
        self::assertStringStartsWith('v=STSv1; id=', $fixes[0]->recordValue);

        self::assertSame('TXT', $fixes[0]->recordType);
        self::assertSame('FILE', $fixes[1]->recordType);
        self::assertStringContainsString('mail.yourdomain.tld', $fixes[1]->recordValue);
        self::assertStringContainsString('mode: testing', $fixes[1]->recordValue);
    }

    public function testKnownMxHostsAreUsedInThePolicyFileInsteadOfAPlaceholder(): void
    {
        $fixes = MtaStsFixSuggester::suggest('example.com', ['reason' => 'no MTA-STS record published'], ['mail.example.com']);

        self::assertStringContainsString('mx: mail.example.com', $fixes[1]->recordValue);
        self::assertStringNotContainsString('yourdomain.tld', $fixes[1]->recordValue);
    }

    public function testAnAlreadyPublishedRecordHasNoSuggestion(): void
    {
        self::assertSame([], MtaStsFixSuggester::suggest('example.com', ['url' => 'https://mta-sts.example.com/.well-known/mta-sts.txt', 'reason' => 'policy file valid'], []));
        self::assertSame([], MtaStsFixSuggester::suggest('example.com', ['url' => 'https://mta-sts.example.com/.well-known/mta-sts.txt', 'reason' => 'policy file did not start with "version: STSv1"'], []));
    }
}
