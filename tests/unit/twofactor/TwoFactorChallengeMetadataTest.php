<?php

namespace Golem15\User\Tests\Unit\TwoFactor;

require_once __DIR__ . '/TwoFactorTestCase.php';

use Golem15\User\Classes\TwoFactor\TwoFactorService;
use Golem15\User\Controllers\TwoFactorApiController;
use Golem15\User\Models\TwoFactorChallenge;

/**
 * D-19 / D-18: failed verifies say how many attempts are left and whether the
 * challenge is spent; recovery success says how many codes are left; one
 * challenge mints at most one JWT.
 */
class TwoFactorChallengeMetadataTest extends TwoFactorTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        $this->enableTwoFactorSettings();
    }

    public function test_wrong_code_reports_attempts_remaining_and_not_expired(): void
    {
        $user = $this->makeUser();
        $secret = $this->enableTotpFor($user);
        $challenge = $this->service()->createChallenge($user);

        [$status, $body] = $this->callJson(fn () => (new TwoFactorApiController())->verify($this->request([
            'challenge_token' => $challenge->token,
            'method' => 'totp',
            'code' => $this->wrongCodeFor($secret),
        ])));

        $this->assertSame(401, $status);
        $this->assertTrue($body['two_factor_failed']);
        $this->assertSame('Invalid verification code.', $body['error']);
        $this->assertSame(4, $body['attempts_remaining']);
        $this->assertFalse($body['challenge_expired']);
    }

    public function test_exhausting_the_challenge_reports_zero_and_expired(): void
    {
        $user = $this->makeUser();
        $secret = $this->enableTotpFor($user);
        $challenge = $this->service()->createChallenge($user);
        $wrong = $this->wrongCodeFor($secret);

        $body = [];
        for ($i = 0; $i < 5; $i++) {
            [$status, $body] = $this->callJson(fn () => (new TwoFactorApiController())->verify($this->request([
                'challenge_token' => $challenge->token,
                'method' => 'totp',
                'code' => $wrong,
            ])));
            $this->assertSame(401, $status);
        }

        $this->assertSame(0, $body['attempts_remaining']);
        $this->assertTrue($body['challenge_expired']);

        // Once spent, even a correct code is refused, and the body still says so.
        [$status, $body] = $this->callJson(fn () => (new TwoFactorApiController())->verify($this->request([
            'challenge_token' => $challenge->token,
            'method' => 'totp',
            'code' => $this->otpAt($secret, $this->currentTimestep()),
        ])));
        $this->assertSame(401, $status);
        $this->assertSame(0, $body['attempts_remaining']);
        $this->assertTrue($body['challenge_expired']);
    }

    public function test_unknown_token_reports_zero_and_expired(): void
    {
        $described = $this->service()->describeChallenge(str_repeat('x', 64));

        $this->assertSame(['attempts_remaining' => 0, 'challenge_expired' => true], $described);
    }

    public function test_recovery_success_reports_codes_remaining(): void
    {
        $user = $this->makeUser();
        $this->enableTotpFor($user);
        $codes = $this->service()->generateRecoveryCodes($user);
        $this->assertCount(10, $codes);
        $challenge = $this->service()->createChallenge($user);

        [$status, $body] = $this->callJson(fn () => (new TwoFactorApiController())->recovery($this->request([
            'challenge_token' => $challenge->token,
            'code' => $codes[0],
        ])));

        $this->assertSame(200, $status);
        $this->assertNotEmpty($body['token']);
        $this->assertSame(9, $body['recovery_codes_remaining']);
    }

    public function test_wrong_recovery_code_reports_attempts_remaining(): void
    {
        $user = $this->makeUser();
        $this->enableTotpFor($user);
        $this->service()->generateRecoveryCodes($user);
        $challenge = $this->service()->createChallenge($user);

        [$status, $body] = $this->callJson(fn () => (new TwoFactorApiController())->recovery($this->request([
            'challenge_token' => $challenge->token,
            'code' => 'AAAAA-AAAAA',
        ])));

        $this->assertSame(401, $status);
        $this->assertTrue($body['two_factor_failed']);
        $this->assertSame(4, $body['attempts_remaining']);
        $this->assertFalse($body['challenge_expired']);
    }

    public function test_webauthn_verify_without_options_carries_metadata(): void
    {
        $user = $this->makeUser();
        $challenge = $this->service()->createChallenge($user);

        [$status, $body] = $this->callJson(fn () => (new TwoFactorApiController())->webauthnVerify($this->request([
            'challenge_token' => $challenge->token,
            'assertion' => ['id' => 'x'],
        ])));

        $this->assertSame(401, $status);
        $this->assertArrayHasKey('attempts_remaining', $body);
        $this->assertArrayHasKey('challenge_expired', $body);
        $this->assertSame(5, $body['attempts_remaining']);
    }

    public function test_completed_challenge_cannot_mint_a_second_jwt(): void
    {
        $user = $this->makeUser();
        $secret = $this->enableTotpFor($user);
        $ts = $this->currentTimestep();
        $service = $this->service();
        $challenge = $service->createChallenge($user);

        $this->assertIsArray($service->verifyChallenge($challenge->token, 'totp', $this->otpAt($secret, $ts)));
        $this->assertFalse($service->verifyChallenge($challenge->token, 'totp', $this->otpAt($secret, $ts + 1)));
    }

    public function test_challenge_claim_is_atomic(): void
    {
        // Two racing verifies hold the same still-open challenge row in memory;
        // only the first conditional UPDATE may succeed.
        $user = $this->makeUser();
        $service = $this->service();
        $challenge = $service->createChallenge($user);
        $copy = TwoFactorChallenge::find($challenge->id);

        $claim = new \ReflectionMethod(TwoFactorService::class, 'claimChallenge');
        $claim->setAccessible(true);

        $this->assertTrue($claim->invoke($service, $challenge));
        $this->assertFalse($claim->invoke($service, $copy));
        $this->assertNotNull(TwoFactorChallenge::find($challenge->id)->completed_at);
    }
}
