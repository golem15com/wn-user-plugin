<?php

namespace Golem15\User\Tests\Unit\TwoFactor;

require_once __DIR__ . '/TwoFactorTestCase.php';

use Golem15\User\Classes\TwoFactor\WebAuthnMethod;

/**
 * D-25: the WebAuthn RP ID comes from config webAuthnRpId when set, and falls
 * back to the app.url host exactly as before when it is empty.
 * D-29: rp.name and the TOTP issuer stay config('app.name').
 */
class WebAuthnRpIdConfigTest extends TwoFactorTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        $this->enableTwoFactorSettings();
    }

    public function test_empty_rp_id_falls_back_to_the_app_url_host(): void
    {
        $this->configureWebAuthn([], 'https://api.example.test');
        $user = $this->makeUser();

        $options = $this->service()->getWebAuthnRegistrationOptions($user)['options'];

        $this->assertSame('api.example.test', $options->publicKey->rp->id);
    }

    public function test_configured_rp_id_wins_for_registration_and_assertion(): void
    {
        $this->configureWebAuthn(['webAuthnRpId' => 'wavepath.org'], 'https://api.example.test');
        $user = $this->makeUser();
        $service = $this->service();

        $create = $service->getWebAuthnRegistrationOptions($user)['options'];
        $get = $service->getWebAuthnAuthenticationOptions($user)['options'];

        $this->assertSame('wavepath.org', $create->publicKey->rp->id);
        $this->assertSame('wavepath.org', $get->publicKey->rpId);
    }

    public function test_whitespace_rp_id_counts_as_empty(): void
    {
        $this->configureWebAuthn(['webAuthnRpId' => '   '], 'https://api.example.test');

        $options = $this->service()->getWebAuthnRegistrationOptions($this->makeUser())['options'];

        $this->assertSame('api.example.test', $options->publicKey->rp->id);
    }

    public function test_configured_rp_id_accepts_a_subdomain_origin_end_to_end(): void
    {
        $this->configureWebAuthn(['webAuthnRpId' => 'wavepath.org'], 'https://api.example.test');
        $user = $this->makeUser();
        $soft = $this->softAuthenticator('wavepath.org', 'https://www.wavepath.org');

        $credential = $this->registerSoftKey($user, $soft);
        $this->assertSame($soft->credentialIdB64(), $credential->credential_id);

        $options = $this->service()->getWebAuthnAuthenticationOptions($user);
        $assertion = $soft->get(base64_decode($options['challenge']));

        $this->assertTrue((new WebAuthnMethod())->verify($user, json_encode($assertion), ['challenge' => $options['challenge']]));
    }

    public function test_rp_name_and_totp_issuer_are_the_app_name(): void
    {
        $this->configureWebAuthn([], 'https://api.example.test', 'Example App');
        $user = $this->makeUser();
        $service = $this->service();

        $options = $service->getWebAuthnRegistrationOptions($user)['options'];
        $this->assertSame('Example App', $options->publicKey->rp->name);

        $totp = $service->setupTotp($user);
        $this->assertStringContainsString('issuer=Example', $totp['qr_code_url']);
        $this->assertStringContainsString(rawurlencode('Example App') . ':', $totp['qr_code_url']);
    }
}
