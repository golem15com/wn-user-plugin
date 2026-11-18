<?php

namespace Golem15\User\Tests\Unit\DeviceFlow;

require_once __DIR__ . '/DeviceFlowTestCase.php';

use Carbon\Carbon;
use Event;
use Golem15\User\Models\DeviceAuthSession;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Log;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

/**
 * D-09 / D-10 / D-12 / D-14: a client holding the PKCE verifier can poll a
 * device session to "confirmed" and redeem a JWT for the confirming user
 * exactly once, inside the redeem window.
 */
class DeviceFlowRedeemTest extends DeviceFlowTestCase
{
    // ---- RFC 7636 verifier check ---------------------------------------------

    public function test_rfc7636_appendix_b_vector_verifies(): void
    {
        $session = new DeviceAuthSession();
        $session->code_challenge = self::RFC_CHALLENGE;

        $this->assertSame('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk', self::RFC_VERIFIER);
        $this->assertSame('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', self::RFC_CHALLENGE);
        $this->assertTrue($session->isRedeemable());
        $this->assertTrue($session->verifyCodeVerifier(self::RFC_VERIFIER));
    }

    public function test_verifier_check_rejects_other_verifiers(): void
    {
        $session = new DeviceAuthSession();
        $session->code_challenge = self::RFC_CHALLENGE;

        $other = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXX';
        $this->assertSame(43, strlen($other));
        $this->assertFalse($session->verifyCodeVerifier($other));
        $this->assertFalse($session->verifyCodeVerifier(substr(self::RFC_VERIFIER, 0, 42)));
        $this->assertFalse($session->verifyCodeVerifier(substr(self::RFC_VERIFIER, 0, 42) . '+'));
    }

    public function test_a_session_without_a_challenge_is_not_redeemable(): void
    {
        $session = new DeviceAuthSession();

        $this->assertFalse($session->isRedeemable());
        $this->assertFalse($session->verifyCodeVerifier(self::RFC_VERIFIER));
    }

    // ---- happy path ----------------------------------------------------------

    public function test_full_flow_initiate_confirm_poll_redeem(): void
    {
        $user = $this->makeUser();
        [$verifier, $challenge] = $this->pkcePair();

        [$status, $init] = $this->initiate(['code_challenge' => $challenge, 'code_challenge_method' => 'S256', 'device_name' => 'WavePath Desktop (Linux)']);
        $this->assertSame(200, $status);
        foreach (['token', 'short_code', 'auth_url', 'expires_at', 'expires_in', 'interval'] as $key) {
            $this->assertArrayHasKey($key, $init['data']);
        }
        $this->assertSame(300, $init['data']['expires_in']);
        $this->assertSame(3, $init['data']['interval']);
        $token = $init['data']['token'];
        $this->assertSame($challenge, $this->deviceSession($token)->code_challenge);

        [$status, $body] = $this->poll($token, $verifier);
        $this->assertSame(200, $status);
        $this->assertSame('pending', $body['data']['status']);
        $this->assertSame(3, $body['data']['interval']);
        $this->assertArrayNotHasKey('redeem_expires_in', $body['data']);

        [$status] = $this->confirmAs($user, $token);
        $this->assertSame(200, $status);

        [$status, $body] = $this->poll($token, $verifier);
        $this->assertSame(200, $status);
        $this->assertSame('confirmed', $body['data']['status']);
        $this->assertGreaterThanOrEqual(1, $body['data']['redeem_expires_in']);
        $this->assertLessThanOrEqual(60, $body['data']['redeem_expires_in']);
        $this->assertArrayNotHasKey('user_id', $body['data']);

        [$status, $body] = $this->redeem($token, $verifier);
        $this->assertSame(200, $status, json_encode($body));
        $this->assertNotEmpty($body['token']);
        $this->assertSame((int) $user->id, (int) $body['user']['id']);
        $this->app->forgetInstance('tymon.jwt');
        $this->assertSame((int) $user->id, (int) JWTAuth::setToken($body['token'])->toUser()->id);

        [$status, $body] = $this->poll($token, $verifier);
        $this->assertSame(200, $status);
        $this->assertSame('used', $body['data']['status']);
    }

    public function test_a_grant_redeems_only_once(): void
    {
        $user = $this->makeUser();
        [$token, $verifier] = $this->initiateRedeemable();
        $this->confirmAs($user, $token);

        [$status] = $this->redeem($token, $verifier);
        $this->assertSame(200, $status);

        [$status, $body] = $this->redeem($token, $verifier);
        $this->assertSame(410, $status);
        $this->assertSame('grant_used', $body['code']);
        $this->assertSame('Grant no longer valid', $body['error']);
    }

    public function test_a_wrong_verifier_gets_the_generic_404_and_does_not_consume_the_grant(): void
    {
        $user = $this->makeUser();
        [$token, $verifier] = $this->initiateRedeemable();
        $this->confirmAs($user, $token);

        [$wrongVerifier] = $this->pkcePair();
        [$status, $body] = $this->redeem($token, $wrongVerifier);
        $this->assertSame(404, $status);
        $this->assertSame(['error' => 'Invalid grant'], $body);

        $session = $this->deviceSession($token);
        $this->assertSame(DeviceAuthSession::STATUS_CONFIRMED, $session->status);
        $this->assertNull($session->used_at);

        [$status] = $this->redeem($token, $verifier);
        $this->assertSame(200, $status);
    }

    // ---- pending / expiry ----------------------------------------------------

    public function test_redeem_while_pending_is_authorization_pending(): void
    {
        [$token, $verifier] = $this->initiateRedeemable();

        [$status, $body] = $this->redeem($token, $verifier);
        $this->assertSame(409, $status);
        $this->assertSame(['error' => 'Authorization pending', 'code' => 'authorization_pending'], $body);
        $this->assertSame(DeviceAuthSession::STATUS_PENDING, $this->deviceSession($token)->status);
    }

    public function test_redeem_after_the_redeem_window_is_expired_token(): void
    {
        $user = $this->makeUser();
        [$token, $verifier] = $this->initiateRedeemable();
        $this->confirmAs($user, $token);

        Carbon::setTestNow(Carbon::now()->addSeconds(61));

        [$status, $body] = $this->redeem($token, $verifier);
        $this->assertSame(410, $status);
        $this->assertSame('expired_token', $body['code']);

        [$status, $body] = $this->poll($token, $verifier);
        $this->assertSame(200, $status);
        $this->assertSame('expired', $body['data']['status']);
        $this->assertSame(DeviceAuthSession::STATUS_EXPIRED, $this->deviceSession($token)->status);
    }

    public function test_poll_marks_a_stale_pending_session_expired(): void
    {
        [$token, $verifier] = $this->initiateRedeemable();

        Carbon::setTestNow(Carbon::now()->addMinutes(6));

        [$status, $body] = $this->poll($token, $verifier);
        $this->assertSame(200, $status);
        $this->assertSame('expired', $body['data']['status']);
        $this->assertSame(DeviceAuthSession::STATUS_EXPIRED, $this->deviceSession($token)->status);
    }

    // ---- input validation / not found -----------------------------------------

    public function test_missing_or_short_verifier_is_422(): void
    {
        [$token, $verifier] = $this->initiateRedeemable();

        foreach ([null, substr($verifier, 0, 42)] as $bad) {
            [$status, $body] = $this->poll($token, $bad);
            $this->assertSame(422, $status);
            $this->assertSame('Validation failed', $body['error']);

            [$status, $body] = $this->redeem($token, $bad);
            $this->assertSame(422, $status);
            $this->assertSame('Validation failed', $body['error']);
        }
    }

    public function test_unknown_token_is_404(): void
    {
        [$verifier] = $this->pkcePair();
        $unknown = str_repeat('a', 64);

        [$status, $body] = $this->poll($unknown, $verifier);
        $this->assertSame(404, $status);
        $this->assertSame(['error' => 'Session not found'], $body);

        [$status, $body] = $this->redeem($unknown, $verifier);
        $this->assertSame(404, $status);
        $this->assertSame(['error' => 'Invalid grant'], $body);
    }

    public function test_a_session_created_without_a_challenge_is_404_for_poll_and_redeem(): void
    {
        $user = $this->makeUser();
        [$status, $init] = $this->initiate([]);
        $this->assertSame(200, $status);
        $token = $init['data']['token'];
        $this->confirmAs($user, $token);

        [$verifier] = $this->pkcePair();
        [$status] = $this->poll($token, $verifier);
        $this->assertSame(404, $status);
        [$status] = $this->redeem($token, $verifier);
        $this->assertSame(404, $status);
        $this->assertSame(DeviceAuthSession::STATUS_CONFIRMED, $this->deviceSession($token)->status);
    }

    public function test_initiate_rejects_a_malformed_challenge_or_method(): void
    {
        [$status, $body] = $this->initiate(['code_challenge' => 'too-short']);
        $this->assertSame(422, $status);
        $this->assertSame('Validation failed', $body['error']);

        [, $challenge] = $this->pkcePair();
        [$status, $body] = $this->initiate(['code_challenge' => $challenge, 'code_challenge_method' => 'plain']);
        $this->assertSame(422, $status);

        // A challenge sent without a method is S256.
        [$status] = $this->initiate(['code_challenge' => $challenge]);
        $this->assertSame(200, $status);
    }

    // ---- events / logs ------------------------------------------------------

    public function test_events_fire_exactly_once_on_success_and_never_on_failure(): void
    {
        $user = $this->makeUser();
        $logins = 0;
        $redeemed = [];
        Event::listen('golem15.user.login', function () use (&$logins) {
            $logins++;
        });
        Event::listen('golem15.user.device.redeemed', function (...$args) use (&$redeemed) {
            $redeemed[] = $args;
        });

        [$token, $verifier] = $this->initiateRedeemable();
        $this->redeem($token, $verifier);                 // pending -> 409
        $this->confirmAs($user, $token);
        [$wrong] = $this->pkcePair();
        $this->redeem($token, $wrong);                    // mismatch -> 404
        $this->assertSame(0, $logins);
        $this->assertCount(0, $redeemed);

        [$status] = $this->redeem($token, $verifier);
        $this->assertSame(200, $status);
        $this->redeem($token, $verifier);                 // used -> 410

        $this->assertSame(1, $logins);
        $this->assertCount(1, $redeemed);
        $this->assertSame((int) $user->id, (int) $redeemed[0][0]->id);
        $this->assertInstanceOf(DeviceAuthSession::class, $redeemed[0][1]);
        $this->assertSame($token, $redeemed[0][1]->token);
        $this->assertSame('127.0.0.1', $redeemed[0][2]);
    }

    public function test_no_log_entry_carries_the_token_verifier_or_jwt(): void
    {
        $logged = [];
        Event::listen(MessageLogged::class, function (MessageLogged $e) use (&$logged) {
            $logged[] = $e->message . ' ' . json_encode($e->context);
        });

        // The capture works: a probe line is seen.
        Log::info('device-flow-log-probe');
        $this->assertNotEmpty(array_filter($logged, fn ($l) => str_contains($l, 'device-flow-log-probe')));

        $user = $this->makeUser();
        [$token, $verifier] = $this->initiateRedeemable();
        $this->poll($token, $verifier);
        $this->confirmAs($user, $token);
        $this->poll($token, $verifier);
        [, $body] = $this->redeem($token, $verifier);
        $this->redeem($token, $verifier);
        $this->poll($token, $verifier);
        $jwt = $body['token'];

        foreach ($logged as $line) {
            $this->assertStringNotContainsString($token, $line);
            $this->assertStringNotContainsString($verifier, $line);
            $this->assertStringNotContainsString($jwt, $line);
        }
    }
}
