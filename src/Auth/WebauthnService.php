<?php

declare(strict_types=1);

namespace App\Auth;

use Cose\Algorithms;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * WebAuthn registration & authentication ceremonies (spec §15.3 — passkeys,
 * preferred over password+TOTP). Built directly against the installed
 * web-auth/webauthn-lib 5.3.5 source (its own doc site serves older
 * examples that don't match this major version's API).
 *
 * Only the 'none' attestation conveyance is requested/accepted — this app
 * has no use for attestation trust chains, and restricting the
 * AttestationStatementSupportManager to NoneAttestationStatementSupport
 * keeps the registration ceremony from needing MDS/certificate-chain setup.
 * userVerification is 'required' throughout: a passkey only satisfies MFA
 * on its own (§15.3) when the authenticator actually performed local user
 * verification (biometric/PIN), not mere possession.
 */
final class WebauthnService
{
    private readonly CeremonyStepManagerFactory $ceremonyFactory;
    private readonly SerializerInterface $serializer;

    public function __construct(
        private readonly string $rpId,
        private readonly string $rpName,
        string $baseUrl,
    ) {
        $this->ceremonyFactory = new CeremonyStepManagerFactory();
        $this->ceremonyFactory->setAllowedOrigins([$baseUrl]);

        $attestationManager = new AttestationStatementSupportManager([new NoneAttestationStatementSupport()]);
        $this->ceremonyFactory->setAttestationStatementSupportManager($attestationManager);
        $this->serializer = (new WebauthnSerializerFactory($attestationManager))->create();
    }

    /** @param list<string> $excludeCredentialIds raw credential ids already registered for this user */
    public function creationOptions(int $userId, string $email, array $excludeCredentialIds): PublicKeyCredentialCreationOptions
    {
        $rp   = PublicKeyCredentialRpEntity::create($this->rpName, $this->rpId);
        $user = PublicKeyCredentialUserEntity::create($email, WebauthnUserHandle::forUser($userId), $email);

        $exclude = array_map(
            static fn (string $id): PublicKeyCredentialDescriptor => PublicKeyCredentialDescriptor::create('public-key', $id),
            $excludeCredentialIds
        );

        return PublicKeyCredentialCreationOptions::create(
            $rp,
            $user,
            random_bytes(32),
            [
                PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_ES256),
                PublicKeyCredentialParameters::create('public-key', Algorithms::COSE_ALGORITHM_RS256),
            ],
            AuthenticatorSelectionCriteria::create(
                userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            ),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            $exclude,
        );
    }

    /** @param list<string> $allowCredentialIds raw credential ids the user may authenticate with */
    public function requestOptions(array $allowCredentialIds): PublicKeyCredentialRequestOptions
    {
        $allow = array_map(
            static fn (string $id): PublicKeyCredentialDescriptor => PublicKeyCredentialDescriptor::create('public-key', $id),
            $allowCredentialIds
        );

        return PublicKeyCredentialRequestOptions::create(
            random_bytes(32),
            $this->rpId,
            $allow,
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
        );
    }

    public function serializeOptions(PublicKeyCredentialCreationOptions|PublicKeyCredentialRequestOptions $options): string
    {
        return $this->serializer->serialize($options, 'json', ['skip_null_values' => true]);
    }

    /**
     * Round-trips options through the same serializer used to send them to
     * the browser. The controller seals the serialized JSON into a
     * short-lived cookie (SealedCookie) between the options and verify
     * requests — there's no session yet during an unauthenticated login,
     * and re-deserializing avoids reconstructing the options by hand (which
     * would risk drifting from what was actually sent).
     */
    public function deserializeCreationOptions(string $json): PublicKeyCredentialCreationOptions
    {
        return $this->serializer->deserialize($json, PublicKeyCredentialCreationOptions::class, 'json');
    }

    public function deserializeRequestOptions(string $json): PublicKeyCredentialRequestOptions
    {
        return $this->serializer->deserialize($json, PublicKeyCredentialRequestOptions::class, 'json');
    }

    public function decodeCredential(string $credentialResponseJson): PublicKeyCredential
    {
        return $this->serializer->deserialize($credentialResponseJson, PublicKeyCredential::class, 'json');
    }

    public function verifyRegistration(PublicKeyCredential $credential, PublicKeyCredentialCreationOptions $options): CredentialRecord
    {
        if (!$credential->response instanceof AuthenticatorAttestationResponse) {
            throw new AuthException('Invalid passkey registration response.');
        }

        $validator = AuthenticatorAttestationResponseValidator::create($this->ceremonyFactory->creationCeremony());

        return $validator->check($credential->response, $options, $this->rpId);
    }

    /** @return CredentialRecord the updated record — persist it (sign counter changed) */
    public function verifyAuthentication(
        PublicKeyCredential $credential,
        PublicKeyCredentialRequestOptions $options,
        CredentialRecord $storedCredential,
        string $expectedUserHandle,
    ): CredentialRecord {
        if (!$credential->response instanceof AuthenticatorAssertionResponse) {
            throw new AuthException('Invalid passkey authentication response.');
        }

        $validator = AuthenticatorAssertionResponseValidator::create($this->ceremonyFactory->requestCeremony());

        return $validator->check(
            $storedCredential,
            $credential->response,
            $options,
            $this->rpId,
            $expectedUserHandle,
        );
    }
}
