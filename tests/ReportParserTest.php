<?php

declare(strict_types=1);

namespace App\Tests;

use App\Ingest\ReportParser;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ReportParserTest extends TestCase
{
    private ReportParser $parser;

    protected function setUp(): void
    {
        $this->parser = new ReportParser();
    }

    public function testParsesValidReport(): void
    {
        $xml    = file_get_contents(__DIR__ . '/fixtures/sample-report.xml');
        $report = $this->parser->parse((string) $xml);

        self::assertSame('silverday.de', $report->domain);
        self::assertSame('google.com', $report->reporterOrg);
        self::assertSame(2, $report->recordCount());
        self::assertSame(49, $report->messageCount());
        self::assertStringContainsString('p=none', $report->policyPublished);
    }

    /**
     * §4.1 — a DOCTYPE has no legitimate place in a DMARC report and is the
     * vector for classic XXE / billion-laughs payloads.
     */
    public function testRejectsDoctype(): void
    {
        $xml = <<<XML
        <?xml version="1.0"?>
        <!DOCTYPE feedback [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <feedback><report_metadata><org_name>&xxe;</org_name></report_metadata></feedback>
        XML;

        $this->expectException(RuntimeException::class);
        $this->parser->parse($xml);
    }

    public function testExternalEntityIsNotResolved(): void
    {
        $xml = <<<XML
        <?xml version="1.0"?>
        <feedback>
          <report_metadata><org_name>test</org_name><report_id>1</report_id>
            <date_range><begin>1</begin><end>2</end></date_range>
          </report_metadata>
          <policy_published><domain>example.com</domain><p>none</p></policy_published>
        </feedback>
        XML;

        $report = $this->parser->parse($xml);
        self::assertSame('example.com', $report->domain);
    }

    public function testSkipsMalformedRecordWithoutFailingReport(): void
    {
        $xml = <<<XML
        <?xml version="1.0"?>
        <feedback>
          <report_metadata><org_name>test</org_name><report_id>1</report_id>
            <date_range><begin>1</begin><end>2</end></date_range>
          </report_metadata>
          <policy_published><domain>example.com</domain><p>none</p></policy_published>
          <record><row><source_ip>not-an-ip</source_ip><count>1</count></row></record>
          <record>
            <row><source_ip>192.0.2.1</source_ip><count>5</count>
              <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
            </row>
          </record>
        </feedback>
        XML;

        $report = $this->parser->parse($xml);

        self::assertSame(1, $report->recordCount(), 'bad record skipped, good record kept');
        self::assertCount(1, $report->warnings);
    }

    public function testRejectsReportWithoutDomain(): void
    {
        $xml = '<?xml version="1.0"?><feedback><report_metadata><org_name>x</org_name>'
             . '<date_range><begin>1</begin><end>2</end></date_range></report_metadata>'
             . '<policy_published><p>none</p></policy_published></feedback>';

        $this->expectException(RuntimeException::class);
        $this->parser->parse($xml);
    }
}
