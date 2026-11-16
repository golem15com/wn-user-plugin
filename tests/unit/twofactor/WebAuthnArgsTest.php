<?php

namespace Golem15\User\Tests\Unit\TwoFactor;

require_once __DIR__ . '/TwoFactorTestCase.php';

/**
 * G1 / D-07: the lbuchs calls use named arguments, so excludeCredentials is
 * actually sent on registration and the usb transport hint survives on
 * assertion. No authenticatorAttachment filter (platform and roaming allowed).
 */
class WebAuthnArgsTest extends TwoFactorTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        $this->enableTwoFactorSettings();
        $this->configureWebAuthn();
    }

    public function test_registration_options_exclude_existing_credentials(): void
    {
        $user = $this->makeUser();
        $soft = $this->softAuthenticator();
        $this->registerSoftKey($user, $soft);

        $options = $this->service()->getWebAuthnRegistrationOptions($user)['options'];

        $this->assertCount(1, $options->publicKey->excludeCredentials);
        $this->assertSame($soft->credentialIdBin(), $options->publicKey->excludeCredentials[0]->id->getBinaryString());
    }

    public function test_registration_options_set_no_authenticator_attachment(): void
    {
        $user = $this->makeUser();
        $this->registerSoftKey($user, $this->softAuthenticator());

        $options = $this->service()->getWebAuthnRegistrationOptions($user)['options'];

        $this->assertObjectNotHasProperty('authenticatorAttachment', $options->publicKey->authenticatorSelection);
    }

    public function test_registration_options_without_credentials_have_empty_exclude_list(): void
    {
        $options = $this->service()->getWebAuthnRegistrationOptions($this->makeUser())['options'];

        $this->assertSame([], $options->publicKey->excludeCredentials);
        $this->assertSame('none', $options->publicKey->attestation);
    }

    public function test_assertion_options_keep_the_usb_transport_hint(): void
    {
        $user = $this->makeUser();
        $this->registerSoftKey($user, $this->softAuthenticator());

        $options = $this->service()->getWebAuthnAuthenticationOptions($user)['options'];

        $this->assertContains('usb', $options->publicKey->allowCredentials[0]->transports);
        $this->assertContains('nfc', $options->publicKey->allowCredentials[0]->transports);
    }

    public function test_user_handle_encoding_is_stable(): void
    {
        $user = $this->makeUser();
        $method = new \Golem15\User\Classes\TwoFactor\WebAuthnMethod();

        $this->assertSame(hex2bin(str_pad(dechex($user->id), 16, '0', STR_PAD_LEFT)), $method->userHandleFor($user->id));

        $options = $this->service()->getWebAuthnRegistrationOptions($user)['options'];
        $this->assertSame($method->userHandleFor($user->id), $options->publicKey->user->id->getBinaryString());
    }
}
