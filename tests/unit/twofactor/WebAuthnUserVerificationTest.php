<?php

namespace Golem15\User\Tests\Unit\TwoFactor;

require_once __DIR__ . '/TwoFactorTestCase.php';

use Golem15\User\Classes\TwoFactor\WebAuthnMethod;
use Golem15\User\Models\Settings;

/**
 * D-05 / D-27: with webAuthnUserVerification=required and
 * webAuthnResidentKey=required the server asks for and enforces user
 * verification and a discoverable credential. With the defaults the options and
 * the verification are what they were before (portal compatibility).
 */
class WebAuthnUserVerificationTest extends TwoFactorTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        $this->enableTwoFactorSettings();
    }

    // ---- defaults -----------------------------------------------------------

    public function test_defaults_ask_for_preferred_uv_and_no_resident_key(): void
    {
        $this->configureWebAuthn();
        $user = $this->makeUser();
        $service = $this->service();

        $create = $service->getWebAuthnRegistrationOptions($user)['options'];
        $this->assertSame('preferred', $create->publicKey->authenticatorSelection->userVerification);
        $this->assertObjectNotHasProperty('residentKey', $create->publicKey->authenticatorSelection);

        $this->registerSoftKey($user, $this->softAuthenticator());
        $get = $this->service()->getWebAuthnAuthenticationOptions($user)['options'];
        $this->assertSame('preferred', $get->publicKey->userVerification);
    }

    public function test_defaults_with_passwordless_on_prefer_a_resident_key(): void
    {
        $this->configureWebAuthn();
        $this->enableTwoFactorSettings(['two_factor_passwordless_login' => true]);

        $create = $this->service()->getWebAuthnRegistrationOptions($this->makeUser())['options'];

        $this->assertSame('preferred', $create->publicKey->authenticatorSelection->residentKey);
        $this->assertFalse($create->publicKey->authenticatorSelection->requireResidentKey);
    }

    public function test_defaults_accept_registration_and_assertion_without_uv(): void
    {
        $this->configureWebAuthn();
        $user = $this->makeUser();
        $soft = $this->softAuthenticator();

        $credential = $this->registerSoftKey($user, $soft, false);
        $this->assertNotNull($credential->id);

        $options = $this->service()->getWebAuthnAuthenticationOptions($user);
        $assertion = $soft->get(base64_decode($options['challenge']), false);

        $this->assertTrue((new WebAuthnMethod())->verify($user, json_encode($assertion), ['challenge' => $options['challenge']]));
    }

    // ---- required -----------------------------------------------------------

    public function test_required_policy_asks_for_uv_and_a_resident_key(): void
    {
        $this->configureWebAuthn(['webAuthnUserVerification' => 'required', 'webAuthnResidentKey' => 'required']);
        $user = $this->makeUser();

        $create = $this->service()->getWebAuthnRegistrationOptions($user)['options'];
        $selection = $create->publicKey->authenticatorSelection;
        $this->assertSame('required', $selection->residentKey);
        $this->assertTrue($selection->requireResidentKey);
        $this->assertSame('required', $selection->userVerification);

        $this->assertSame('required', $this->service()->getPasswordlessAuthenticationOptions()['options']->publicKey->userVerification);
    }

    public function test_required_policy_rejects_registration_without_uv(): void
    {
        $this->configureWebAuthn(['webAuthnUserVerification' => 'required', 'webAuthnResidentKey' => 'required']);

        $this->expectException(\Exception::class);
        $this->registerSoftKey($this->makeUser(), $this->softAuthenticator(), false);
    }

    public function test_required_policy_accepts_registration_with_uv(): void
    {
        $this->configureWebAuthn(['webAuthnUserVerification' => 'required', 'webAuthnResidentKey' => 'required']);

        $credential = $this->registerSoftKey($this->makeUser(), $this->softAuthenticator(), true);

        $this->assertNotNull($credential->id);
    }

    public function test_required_policy_enforces_uv_on_assertion(): void
    {
        $this->configureWebAuthn(['webAuthnUserVerification' => 'required', 'webAuthnResidentKey' => 'required']);
        $user = $this->makeUser();
        $soft = $this->softAuthenticator();
        $this->registerSoftKey($user, $soft, true);

        $options = $this->service()->getWebAuthnAuthenticationOptions($user);
        $this->assertSame('required', $options['options']->publicKey->userVerification);
        $method = new WebAuthnMethod();

        $withoutUv = $soft->get(base64_decode($options['challenge']), false, null, 1);
        $this->assertFalse($method->verify($user, json_encode($withoutUv), ['challenge' => $options['challenge']]));

        $withUv = $soft->get(base64_decode($options['challenge']), true, null, 2);
        $this->assertTrue($method->verify($user, json_encode($withUv), ['challenge' => $options['challenge']]));
    }

    public function test_invalid_policy_values_fall_back_to_defaults(): void
    {
        $this->configureWebAuthn(['webAuthnUserVerification' => 'always', 'webAuthnResidentKey' => 'sometimes']);
        Settings::set('two_factor_passwordless_login', false);

        $create = $this->service()->getWebAuthnRegistrationOptions($this->makeUser())['options'];

        $this->assertSame('preferred', $create->publicKey->authenticatorSelection->userVerification);
        $this->assertObjectNotHasProperty('residentKey', $create->publicKey->authenticatorSelection);
    }
}
