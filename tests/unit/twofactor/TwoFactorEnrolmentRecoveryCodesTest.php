<?php

namespace Golem15\User\Tests\Unit\TwoFactor;

require_once __DIR__ . '/TwoFactorTestCase.php';

use Golem15\User\Controllers\TwoFactorApiController;
use Golem15\User\Models\WebAuthnCredential;

/**
 * D-08 / D-22: the first enrolment returns the 10 plaintext recovery codes once;
 * later enrolments do not. Registering a passkey re-enables the webauthn method
 * even after every key was removed earlier.
 */
class TwoFactorEnrolmentRecoveryCodesTest extends TwoFactorTestCase
{
    private const CODE_PATTERN = '/^[A-Z0-9]{5}-[A-Z0-9]{5}$/';

    public function setUp(): void
    {
        parent::setUp();
        $this->enableTwoFactorSettings();
        $this->configureWebAuthn();
    }

    private function confirmTotp($user): array
    {
        $secret = $this->google2fa->generateSecretKey();
        $jwt = $this->jwtFor($user);

        return $this->callJson(fn () => (new TwoFactorApiController())->totpConfirm($this->request([
            'secret' => $secret,
            'code' => $this->otpAt($secret, $this->currentTimestep()),
        ], $jwt)));
    }

    private function registerPasskey($user): array
    {
        $jwt = $this->jwtFor($user);
        [, $options] = $this->callJson(fn () => (new TwoFactorApiController())->webauthnRegisterOptions($this->request([], $jwt)));
        $attestation = $this->softAuthenticator()->create(base64_decode($options['challenge']));

        return $this->callJson(fn () => (new TwoFactorApiController())->webauthnRegister($this->request([
            'attestation' => $attestation,
        ], $jwt)));
    }

    public function test_first_totp_confirm_returns_ten_recovery_codes(): void
    {
        [$status, $body] = $this->confirmTotp($this->makeUser());

        $this->assertSame(200, $status, json_encode($body));
        $this->assertCount(10, $body['recovery_codes']);
        foreach ($body['recovery_codes'] as $code) {
            $this->assertMatchesRegularExpression(self::CODE_PATTERN, $code);
        }
    }

    public function test_later_enrolment_returns_no_recovery_codes(): void
    {
        $user = $this->makeUser();
        $this->confirmTotp($user);

        [$status, $body] = $this->registerPasskey($user);

        $this->assertSame(200, $status, json_encode($body));
        $this->assertArrayNotHasKey('recovery_codes', $body);
    }

    public function test_first_passkey_returns_recovery_codes(): void
    {
        [$status, $body] = $this->registerPasskey($this->makeUser());

        $this->assertSame(200, $status, json_encode($body));
        $this->assertCount(10, $body['recovery_codes']);
    }

    public function test_fresh_codes_are_consumed_once(): void
    {
        $user = $this->makeUser();
        $service = $this->service();
        $service->confirmTotp($user, $secret = $this->google2fa->generateSecretKey(), $this->otpAt($secret, $this->currentTimestep()));

        $this->assertCount(10, $service->consumeFreshRecoveryCodes());
        $this->assertNull($service->consumeFreshRecoveryCodes());
    }

    public function test_passkey_re_enables_two_factor_after_all_keys_were_removed(): void
    {
        $user = $this->makeUser();
        $this->registerPasskey($user);
        $service = $this->service();
        $this->assertTrue($service->isEnabledForUser($user));

        $credentialId = WebAuthnCredential::where('user_id', $user->id)->value('id');
        $this->assertTrue($service->removeWebAuthnCredential($user, $credentialId));
        $this->assertFalse($this->service()->isEnabledForUser($user));

        [$status, $body] = $this->registerPasskey($user);

        $this->assertSame(200, $status, json_encode($body));
        $this->assertTrue($this->service()->isEnabledForUser($user));
        $this->assertTrue($body['status']['enabled']);
    }
}
