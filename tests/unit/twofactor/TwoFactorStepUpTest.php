<?php

namespace Golem15\User\Tests\Unit\TwoFactor;

require_once __DIR__ . '/TwoFactorTestCase.php';

use Cache;
use Golem15\User\Classes\TwoFactor\TwoFactorService;
use Golem15\User\Controllers\TwoFactorApiController;
use Golem15\User\Models\Settings;
use Golem15\User\Models\TwoFactorMethod;
use Golem15\User\Models\User as UserModel;
use Golem15\User\Models\WebAuthnCredential;
use Illuminate\Support\Facades\RateLimiter;

/**
 * D-12: with two_factor_step_up_required on, turning off TOTP, removing a
 * passkey and regenerating recovery codes need a fresh second factor (or the
 * account password, when the user set one). A stolen JWT alone cannot strip
 * 2FA. With the Setting off (the default) these endpoints behave as before.
 */
class TwoFactorStepUpTest extends TwoFactorTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        $this->configureWebAuthn();
        $this->enableTwoFactorSettings();
    }

    protected function stepUp(bool $on): void
    {
        Settings::set('two_factor_step_up_required', $on);
    }

    protected function controller(): TwoFactorApiController
    {
        $this->service();
        app()->forgetInstance(TwoFactorService::class);

        return new TwoFactorApiController();
    }

    /**
     * @return array{0: int, 1: array}
     */
    protected function disableTotp(UserModel $user, array $body = []): array
    {
        return $this->callJson(fn () => $this->controller()->totpDisable(
            $this->request($body, $this->jwtFor($user), 'DELETE')
        ));
    }

    /**
     * @return array{0: int, 1: array}
     */
    protected function removeKey(UserModel $user, int $id, array $body = []): array
    {
        return $this->callJson(fn () => $this->controller()->webauthnRemove(
            $this->request($body, $this->jwtFor($user), 'DELETE'),
            $id
        ));
    }

    /**
     * @return array{0: int, 1: array}
     */
    protected function regenerate(UserModel $user, array $body = []): array
    {
        return $this->callJson(fn () => $this->controller()->regenerateRecoveryCodes(
            $this->request($body, $this->jwtFor($user))
        ));
    }

    /**
     * @return array{0: int, 1: array}
     */
    protected function stepUpOptions(UserModel $user): array
    {
        return $this->callJson(fn () => $this->controller()->stepUpWebauthnOptions(
            $this->request([], $this->jwtFor($user))
        ));
    }

    /**
     * @return array{0: UserModel, 1: string}
     */
    protected function totpUser(array $attrs = []): array
    {
        $user = $this->makeUser($attrs);
        $secret = $this->enableTotpFor($user);

        return [$user, $secret];
    }

    protected function freshTotp(string $secret): array
    {
        return ['step_up' => ['type' => 'totp', 'code' => $this->otpAt($secret, $this->currentTimestep())]];
    }

    protected function assertStepUpFailed(array $result): void
    {
        [$status, $body] = $result;
        $this->assertSame(403, $status, json_encode($body));
        $this->assertTrue($body['step_up_failed'] ?? false);
    }

    protected function totpEnabled(UserModel $user): bool
    {
        return TwoFactorMethod::where('user_id', $user->id)
            ->where('method', TwoFactorMethod::METHOD_TOTP)
            ->where('is_enabled', true)
            ->exists();
    }

    // ---- Setting off: today's behaviour --------------------------------------

    public function test_setting_defaults_to_off(): void
    {
        $this->assertFalse($this->service()->isStepUpRequired());
    }

    public function test_setting_off_totp_disable_needs_no_proof(): void
    {
        [$user] = $this->totpUser();

        [$status] = $this->disableTotp($user);

        $this->assertSame(200, $status);
        $this->assertFalse($this->totpEnabled($user));
    }

    public function test_setting_off_webauthn_remove_needs_no_proof(): void
    {
        $user = $this->makeUser();
        $credential = $this->registerSoftKey($user, $this->softAuthenticator());

        [$status] = $this->removeKey($user, $credential->id);

        $this->assertSame(200, $status);
    }

    public function test_setting_off_regenerate_keeps_the_password_check(): void
    {
        [$user] = $this->totpUser();

        [$status, $body] = $this->regenerate($user);
        $this->assertSame(403, $status);
        $this->assertSame('Password confirmation required.', $body['error']);
        $this->assertArrayNotHasKey('step_up_failed', $body);

        [$status, $body] = $this->regenerate($user, ['password' => 'originalpass1']);
        $this->assertSame(200, $status);
        $this->assertCount(10, $body['recovery_codes']);
    }

    // ---- Setting on: TOTP proof ----------------------------------------------

    public function test_setting_on_without_proof_is_refused(): void
    {
        $this->stepUp(true);
        [$user] = $this->totpUser();

        $this->assertStepUpFailed($this->disableTotp($user));
        $this->assertTrue($this->totpEnabled($user));
    }

    public function test_setting_on_a_fresh_totp_code_is_accepted(): void
    {
        $this->stepUp(true);
        [$user, $secret] = $this->totpUser();

        [$status] = $this->disableTotp($user, $this->freshTotp($secret));

        $this->assertSame(200, $status);
        $this->assertFalse($this->totpEnabled($user));
    }

    public function test_setting_on_the_login_totp_code_cannot_be_replayed(): void
    {
        $this->stepUp(true);
        [$user, $secret] = $this->totpUser();
        $code = $this->otpAt($secret, $this->currentTimestep());

        $service = $this->service();
        $this->assertIsArray($service->verifyChallenge($service->createChallenge($user)->token, 'totp', $code));

        $this->assertStepUpFailed($this->disableTotp($user, ['step_up' => ['type' => 'totp', 'code' => $code]]));
        $this->assertTrue($this->totpEnabled($user));
    }

    // ---- Setting on: password proof ------------------------------------------

    public function test_setting_on_password_proof_works_for_a_self_set_password(): void
    {
        $this->stepUp(true);
        [$user] = $this->totpUser();
        $user->has_self_set_password = true;
        $user->forceSave();

        [$status] = $this->disableTotp($user, ['step_up' => ['type' => 'password', 'password' => 'originalpass1']]);

        $this->assertSame(200, $status);
    }

    public function test_setting_on_password_proof_is_refused_for_a_placeholder_password(): void
    {
        $this->stepUp(true);
        [$user] = $this->totpUser();
        $user->has_self_set_password = false;
        $user->forceSave();

        $this->assertStepUpFailed(
            $this->disableTotp($user, ['step_up' => ['type' => 'password', 'password' => 'originalpass1']])
        );
    }

    public function test_setting_on_a_wrong_password_is_refused(): void
    {
        $this->stepUp(true);
        [$user] = $this->totpUser();

        $this->assertStepUpFailed(
            $this->disableTotp($user, ['step_up' => ['type' => 'password', 'password' => 'not-the-password']])
        );
    }

    public function test_setting_on_regenerate_accepts_the_legacy_password_field(): void
    {
        $this->stepUp(true);
        [$user] = $this->totpUser();

        [$status, $body] = $this->regenerate($user, ['password' => 'originalpass1']);

        $this->assertSame(200, $status);
        $this->assertCount(10, $body['recovery_codes']);
    }

    public function test_setting_on_regenerate_without_proof_is_refused(): void
    {
        $this->stepUp(true);
        [$user] = $this->totpUser();

        $this->assertStepUpFailed($this->regenerate($user));
    }

    public function test_setting_on_unknown_proof_type_is_refused(): void
    {
        $this->stepUp(true);
        [$user] = $this->totpUser();

        $this->assertStepUpFailed($this->disableTotp($user, ['step_up' => ['type' => 'magic']]));
    }

    // ---- Setting on: passkey proof -------------------------------------------

    public function test_step_up_options_need_a_registered_passkey(): void
    {
        $this->stepUp(true);
        [$user] = $this->totpUser();

        [$status, $body] = $this->stepUpOptions($user);

        $this->assertSame(422, $status);
        $this->assertSame('No passkey registered.', $body['error']);
    }

    public function test_setting_on_a_passkey_proof_is_accepted_once(): void
    {
        $this->stepUp(true);
        [$user, $secret] = $this->totpUser();
        $soft = $this->softAuthenticator();
        $this->registerSoftKey($user, $soft);

        [$status, $body] = $this->stepUpOptions($user);
        $this->assertSame(200, $status);
        $this->assertArrayHasKey('options', $body);
        $this->assertArrayNotHasKey('challenge', $body);

        $challenge = Cache::get('2fa-stepup:' . $user->id);
        $this->assertIsString($challenge);
        $proof = ['step_up' => ['type' => 'webauthn', 'assertion' => $soft->get(base64_decode($challenge))]];

        [$status] = $this->regenerate($user, $proof);
        $this->assertSame(200, $status);

        // Same assertion again: the server-held challenge is spent.
        $this->assertStepUpFailed($this->disableTotp($user, $proof));
        $this->assertTrue($this->totpEnabled($user));
    }

    public function test_setting_on_a_passkey_proof_removes_a_passkey(): void
    {
        $this->stepUp(true);
        $user = $this->makeUser();
        $soft = $this->softAuthenticator();
        $this->registerSoftKey($user, $soft);
        $second = $this->registerSoftKey($user, $this->softAuthenticator());

        $this->stepUpOptions($user);
        $challenge = Cache::get('2fa-stepup:' . $user->id);
        $proof = ['step_up' => ['type' => 'webauthn', 'assertion' => $soft->get(base64_decode($challenge))]];

        [$status] = $this->removeKey($user, $second->id, $proof);

        $this->assertSame(200, $status);
        $this->assertNull(WebAuthnCredential::find($second->id));
    }

    public function test_setting_on_webauthn_remove_without_proof_is_refused(): void
    {
        $this->stepUp(true);
        $user = $this->makeUser();
        $credential = $this->registerSoftKey($user, $this->softAuthenticator());

        $this->assertStepUpFailed($this->removeKey($user, $credential->id));
        $this->assertNotNull(WebAuthnCredential::find($credential->id));
    }

    // ---- Setting on: ownership and rate limit --------------------------------

    public function test_removing_another_users_credential_is_still_404_after_a_valid_proof(): void
    {
        $this->stepUp(true);
        [$user, $secret] = $this->totpUser();
        $other = $this->makeUser();
        $foreign = $this->registerSoftKey($other, $this->softAuthenticator());

        [$status] = $this->removeKey($user, $foreign->id, $this->freshTotp($secret));

        $this->assertSame(404, $status);
        $this->assertNotNull(WebAuthnCredential::find($foreign->id));
    }

    public function test_setting_on_the_eleventh_failed_proof_in_a_minute_is_429(): void
    {
        $this->stepUp(true);
        [$user, $secret] = $this->totpUser();
        RateLimiter::clear('2fa-step-up:' . $user->id);
        $wrong = ['step_up' => ['type' => 'totp', 'code' => $this->wrongCodeFor($secret)]];

        for ($i = 1; $i <= 10; $i++) {
            $this->assertStepUpFailed($this->disableTotp($user, $wrong));
        }

        [$status, $body] = $this->disableTotp($user, $this->freshTotp($secret));

        $this->assertSame(429, $status);
        $this->assertArrayHasKey('retry_after', $body);
        $this->assertTrue($this->totpEnabled($user));
    }
}
