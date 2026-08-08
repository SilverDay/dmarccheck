<?php

declare(strict_types=1);

namespace App\Tests\Auth;

use App\Auth\TotpService;
use OTPHP\TOTP;
use PHPUnit\Framework\TestCase;

final class TotpServiceTest extends TestCase
{
    private TotpService $totp;

    protected function setUp(): void
    {
        $this->totp = new TotpService(base64_encode(sodium_crypto_secretbox_keygen()));
    }

    public function testValidCodeVerifies(): void
    {
        $data = $this->totp->generate('alice@example.com', 'DMARC Analyzer');
        $code = TOTP::createFromSecret($data['secret'])->now();

        self::assertTrue($this->totp->verify($data['encryptedSecret'], $code));
    }

    public function testWrongCodeFailsVerification(): void
    {
        $data = $this->totp->generate('alice@example.com', 'DMARC Analyzer');

        self::assertFalse($this->totp->verify($data['encryptedSecret'], '000000'));
    }

    public function testNonNumericOrEmptyCodeFailsVerification(): void
    {
        $data = $this->totp->generate('alice@example.com', 'DMARC Analyzer');

        self::assertFalse($this->totp->verify($data['encryptedSecret'], ''));
        self::assertFalse($this->totp->verify($data['encryptedSecret'], 'abcdef'));
    }

    public function testCodeWithinLeewayWindowVerifies(): void
    {
        $data              = $this->totp->generate('alice@example.com', 'DMARC Analyzer');
        $totp              = TOTP::createFromSecret($data['secret']);
        $codeTenSecondsAgo = $totp->at(time() - 10);

        self::assertTrue($this->totp->verify($data['encryptedSecret'], $codeTenSecondsAgo));
    }

    public function testEncryptedSecretIsNotThePlaintext(): void
    {
        $data = $this->totp->generate('alice@example.com', 'DMARC Analyzer');

        self::assertStringNotContainsString($data['secret'], $data['encryptedSecret']);
    }

    public function testProvisioningUriContainsIssuerAndLabel(): void
    {
        $data = $this->totp->generate('alice@example.com', 'DMARC Analyzer');

        self::assertStringContainsString('DMARC%20Analyzer', $data['provisioningUri']);
        self::assertStringContainsString('alice%40example.com', $data['provisioningUri']);
    }

    public function testWrongEncryptionKeyCannotDecrypt(): void
    {
        $data = $this->totp->generate('alice@example.com', 'DMARC Analyzer');
        $code = TOTP::createFromSecret($data['secret'])->now();

        $otherTotp = new TotpService(base64_encode(sodium_crypto_secretbox_keygen()));

        $this->expectException(\RuntimeException::class);
        $otherTotp->verify($data['encryptedSecret'], $code);
    }
}
