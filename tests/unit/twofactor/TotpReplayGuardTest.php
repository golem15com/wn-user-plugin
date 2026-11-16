<?php

namespace Golem15\User\Tests\Unit\TwoFactor;

require_once __DIR__ . '/TwoFactorTestCase.php';

use Golem15\User\Classes\TwoFactor\TotpMethod;
use Golem15\User\Models\TwoFactorMethod;

/**
 * D-28: a TOTP code already accepted for a user is refused if presented again
 * inside its window. Always on, no Settings flag.
 */
class TotpReplayGuardTest extends TwoFactorTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        $this->enableTwoFactorSettings();
    }

    public function test_same_code_is_refused_on_a_second_challenge(): void
    {
        $user = $this->makeUser();
        $secret = $this->enableTotpFor($user);
        $code = $this->otpAt($secret, $this->currentTimestep());
        $service = $this->service();

        $first = $service->createChallenge($user);
        $this->assertIsArray($service->verifyChallenge($first->token, 'totp', $code));

        $second = $service->createChallenge($user);
        $this->assertFalse($service->verifyChallenge($second->token, 'totp', $code));
    }

    public function test_code_for_the_next_timestep_still_succeeds_after_a_replay_refusal(): void
    {
        $user = $this->makeUser();
        $secret = $this->enableTotpFor($user);
        $ts = $this->currentTimestep();
        $service = $this->service();

        $this->assertIsArray($service->verifyChallenge($service->createChallenge($user)->token, 'totp', $this->otpAt($secret, $ts)));
        $this->assertFalse($service->verifyChallenge($service->createChallenge($user)->token, 'totp', $this->otpAt($secret, $ts)));

        $next = $this->otpAt($secret, $ts + 1);
        $this->assertIsArray($service->verifyChallenge($service->createChallenge($user)->token, 'totp', $next));
    }

    public function test_confirmation_code_cannot_then_be_used_to_sign_in(): void
    {
        $user = $this->makeUser();
        $secret = $this->google2fa->generateSecretKey();
        $code = $this->otpAt($secret, $this->currentTimestep());
        $service = $this->service();

        $this->assertTrue($service->confirmTotp($user, $secret, $code));

        $challenge = $service->createChallenge($user);
        $this->assertFalse($service->verifyChallenge($challenge->token, 'totp', $code));
    }

    public function test_current_code_fails_when_its_timestep_was_already_claimed(): void
    {
        // Simulates losing the concurrent race: another request claimed this
        // timestep between our read and our conditional UPDATE.
        $user = $this->makeUser();
        $secret = $this->enableTotpFor($user);
        $ts = $this->currentTimestep();

        TwoFactorMethod::where('user_id', $user->id)
            ->where('method', TwoFactorMethod::METHOD_TOTP)
            ->update(['last_totp_timestep' => $ts]);

        $service = $this->service();
        $challenge = $service->createChallenge($user);

        $this->assertFalse($service->verifyChallenge($challenge->token, 'totp', $this->otpAt($secret, $ts)));
    }

    public function test_accepted_timestep_is_persisted_on_the_method_row(): void
    {
        $user = $this->makeUser();
        $secret = $this->enableTotpFor($user);
        $ts = $this->currentTimestep();

        $this->assertTrue((new TotpMethod())->verify($user, $this->otpAt($secret, $ts)));

        $stored = TwoFactorMethod::where('user_id', $user->id)->value('last_totp_timestep');
        $this->assertSame($ts, (int) $stored);
    }

    public function test_verify_against_secret_is_unchanged_for_portal(): void
    {
        $secret = $this->google2fa->generateSecretKey();
        $code = $this->otpAt($secret, $this->currentTimestep());
        $totp = new TotpMethod();

        $this->assertTrue($totp->verifyAgainstSecret($secret, $code));
        // Stateless: the same code verifies again against the bare secret.
        $this->assertTrue($totp->verifyAgainstSecret($secret, $code));
    }
}
