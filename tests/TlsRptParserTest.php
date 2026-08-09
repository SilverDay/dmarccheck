<?php

declare(strict_types=1);

namespace App\Tests;

use App\Ingest\TlsRptParser;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class TlsRptParserTest extends TestCase
{
    private TlsRptParser $parser;

    protected function setUp(): void
    {
        $this->parser = new TlsRptParser();
    }

    public function testParsesValidReport(): void
    {
        $json   = file_get_contents(__DIR__ . '/fixtures/sample-tls-rpt-report.json');
        $report = $this->parser->parse((string) $json);

        self::assertSame('google inc.', $report->organizationName);
        self::assertSame('2026080100000-abcdef@google.com', $report->reportId);
        self::assertSame(2, $report->policyCount());
        self::assertSame([], $report->warnings);

        $sts = $report->policies[0];
        self::assertSame('silverday.de', $sts['domain']);
        self::assertSame('sts', $sts['policy_type']);
        self::assertSame(5326, $sts['success_count']);
        self::assertSame(3, $sts['failure_count']);
        self::assertStringContainsString('mode: enforce', (string) $sts['policy_string']);
        self::assertStringContainsString('*.mail.silverday.de', (string) $sts['mx_host']);
        self::assertCount(1, $sts['failure_details']);

        $detail = $sts['failure_details'][0];
        self::assertSame('certificate-expired', $detail['result_type']);
        self::assertSame('2001:db8:abcd:12::1', $detail['sending_mta_ip']);
        self::assertSame('mx1.mail.silverday.de', $detail['receiving_mx_hostname']);
        self::assertSame('mx1.mail.silverday.de', $detail['receiving_mx_helo']);
        self::assertSame('2001:db8:abcd:13::1', $detail['receiving_ip']);
        self::assertSame(3, $detail['failed_session_count']);
        self::assertSame('https://silverday.de/report_info?id=5065427c', $detail['additional_information']);
        self::assertSame('X509_V_ERR_CERT_HAS_EXPIRED', $detail['failure_reason_code']);

        $tlsa = $report->policies[1];
        self::assertSame('tourl.at', $tlsa['domain']);
        self::assertSame('tlsa', $tlsa['policy_type']);
        self::assertSame(0, $tlsa['failure_count']);
        self::assertSame([], $tlsa['failure_details']);
    }

    public function testParsesIsoDatetimeAsUtc(): void
    {
        $json   = file_get_contents(__DIR__ . '/fixtures/sample-tls-rpt-report.json');
        $report = $this->parser->parse((string) $json);

        self::assertSame('2026-08-01 00:00:00', $report->dateBegin->format('Y-m-d H:i:s'));
        self::assertSame('UTC', $report->dateBegin->getTimezone()->getName());
        self::assertSame('2026-08-01 23:59:59', $report->dateEnd->format('Y-m-d H:i:s'));
    }

    public function testSkipsMalformedPolicyWithoutFailingReport(): void
    {
        $json = <<<JSON
        {
          "organization-name": "test",
          "report-id": "1",
          "date-range": {"start-datetime": "2026-01-01T00:00:00Z", "end-datetime": "2026-01-02T00:00:00Z"},
          "policies": [
            {"policy": {"policy-type": "bogus", "policy-domain": "example.com"}},
            {"policy": {"policy-type": "none-policy-found", "policy-domain": "example.com"}},
            {"policy": {"policy-type": "no-policy-found", "policy-domain": "example.com"}, "summary": {"total-successful-session-count": 1, "total-failure-session-count": 0}}
          ]
        }
        JSON;

        $report = $this->parser->parse($json);

        self::assertSame(1, $report->policyCount(), 'bad policies skipped, good one kept');
        self::assertCount(2, $report->warnings);
    }

    public function testSkipsMalformedFailureDetailWithoutFailingPolicy(): void
    {
        $json = <<<JSON
        {
          "organization-name": "test",
          "report-id": "1",
          "date-range": {"start-datetime": "2026-01-01T00:00:00Z", "end-datetime": "2026-01-02T00:00:00Z"},
          "policies": [
            {
              "policy": {"policy-type": "sts", "policy-domain": "example.com"},
              "summary": {"total-successful-session-count": 1, "total-failure-session-count": 2},
              "failure-details": [
                {"sending-mta-ip": "192.0.2.1"},
                {"result-type": "sts-policy-invalid", "failed-session-count": 2}
              ]
            }
          ]
        }
        JSON;

        $report = $this->parser->parse($json);

        self::assertSame(1, $report->policyCount());
        self::assertCount(1, $report->policies[0]['failure_details'], 'entry missing result-type skipped, good one kept');
        self::assertCount(1, $report->warnings);
    }

    public function testTreatsMissingOrInvalidOptionalIpsAsNull(): void
    {
        $json = <<<JSON
        {
          "organization-name": "test",
          "report-id": "1",
          "date-range": {"start-datetime": "2026-01-01T00:00:00Z", "end-datetime": "2026-01-02T00:00:00Z"},
          "policies": [
            {
              "policy": {"policy-type": "sts", "policy-domain": "example.com"},
              "summary": {"total-successful-session-count": 0, "total-failure-session-count": 1},
              "failure-details": [
                {"result-type": "validation-failure", "sending-mta-ip": "not-an-ip"}
              ]
            }
          ]
        }
        JSON;

        $report = $this->parser->parse($json);
        $detail = $report->policies[0]['failure_details'][0];

        self::assertNull($detail['sending_mta_ip']);
        self::assertNull($detail['receiving_ip']);
        self::assertSame('validation-failure', $detail['result_type']);
    }

    public function testRejectsMalformedJson(): void
    {
        $this->expectException(RuntimeException::class);
        $this->parser->parse('{not valid json');
    }

    public function testRejectsReportMissingRequiredTopLevelFields(): void
    {
        $this->expectException(RuntimeException::class);
        $this->parser->parse('{"organization-name": "test"}');
    }
}
