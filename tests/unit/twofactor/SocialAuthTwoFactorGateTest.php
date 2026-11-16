<?php

namespace Golem15\User\Tests\Unit\TwoFactor;

require_once __DIR__ . '/TwoFactorTestCase.php';

use ApplicationException;
use Auth;
use Cache;
use Event;
use Golem15\User\Components\SocialAuth;
use Golem15\User\Controllers\ApiController;
use Golem15\User\Models\Settings;
use Golem15\User\Models\TwoFactorChallenge;
use Golem15\User\Models\User as UserModel;
use Illuminate\Http\Request;
use Laravel\Socialite\Contracts\User as SocialiteUser;
use Laravel\Socialite\Two\User as SocialiteTwoUser;
use ReflectionMethod;

/**
 * D-09: Google (SocialAuth, SPA mode) is only the first factor for a 2FA user.
 *
 * Every SocialAuth JWT mint point hands off a challenge instead of a token when
 * the user has 2FA on, the login event waits for the second factor, and the
 * Winter-session-plus-link bypass is closed. With 2FA off every payload is
 * byte-identical to before (asserted by key sets). Also covers the D-03
 * trusted-device completion helper and pins D-13 (enabling 2FA does not sign
 * existing JWTs out).
 */
class SocialAuthTwoFactorGateTest extends TwoFactorTestCase
{
    private const LEGACY_KEYS = ['token', 'user', 'action', 'return_to'];
    private const CHALLENGE_KEYS = ['two_factor_required', 'challenge_token', 'available_methods', 'expires_at', 'action', 'return_to'];

    protected int $logins = 0;

    public function setUp(): void
    {
        parent::setUp();
        $this->enableTwoFactorSettings();

        session(['oauth_context' => [
            'mode' => 'spa',
            'frontend_callback' => 'https://www.example.test/auth/oauth/callback',
            'return_to' => '/diary',
            'action' => 'login',
        ]]);

        $this->logins = 0;
        Event::listen('golem15.user.login', function () {
            $this->logins++;
        });
    }

    protected function invoke(SocialAuth $component, string $method, array $args)
    {
        $ref = new ReflectionMethod(SocialAuth::class, $method);
        $ref->setAccessible(true);

        return $ref->invokeArgs($component, $args);
    }

    protected function socialiteUser(string $email, string $id = 'google-id-1'): SocialiteUser
    {
        $user = new SocialiteTwoUser();
        $user->map(['id' => $id, 'name' => 'Social Tester', 'email' => $email, 'avatar' => null]);
        $user->setRaw(['email_verified' => true]);
        $user->setToken('tok')->setRefreshToken('refresh')->setExpiresIn(3600);

        return $user;
    }

    protected function twoFactorUser(): UserModel
    {
        $user = $this->makeUser();
        $this->enableTotpFor($user);

        return $user;
    }

    /**
     * The cached oauth-complete payload behind a SocialAuth SPA redirect.
     */
    protected function cachedCompletion($redirect): array
    {
        parse_str((string) parse_url($redirect->getTargetUrl(), PHP_URL_QUERY), $query);
        $this->assertNotEmpty($query['code'] ?? null);

        $payload = Cache::get('oauth-complete:' . $query['code']);
        $this->assertIsArray($payload);

        return ['code' => $query['code'], 'payload' => $payload];
    }

    protected function sortedKeys(array $data): array
    {
        $keys = array_keys($data);
        sort($keys);

        return $keys;
    }

    protected function assertKeySet(array $expected, array $data): void
    {
        sort($expected);
        $this->assertSame($expected, $this->sortedKeys($data));
    }

    protected function pendingPayload(string $email): array
    {
        return [
            'provider' => 'google',
            'provider_id' => 'google-pending-1',
            'token' => 'tok',
            'refresh_token' => 'refresh',
            'expires_in' => 3600,
            'name' => 'Social Tester',
            'email' => $email,
            'avatar' => null,
            'return_to' => '/diary',
            'email_verified' => true,
            'reason' => null,
        ];
    }

    // ---- (1) completeSuccessfulAuth -------------------------------------------

    public function test_complete_successful_auth_without_2fa_keeps_the_legacy_payload(): void
    {
        $user = $this->makeUser();

        $completion = $this->cachedCompletion($this->invoke(new SocialAuth(), 'completeSuccessfulAuth', [$user, 'login', 'ok']));

        $this->assertKeySet(self::LEGACY_KEYS, $completion['payload']);
        $this->assertSame('/diary', $completion['payload']['return_to']);
    }

    public function test_complete_successful_auth_with_2fa_hands_off_a_challenge(): void
    {
        $user = $this->twoFactorUser();

        $completion = $this->cachedCompletion($this->invoke(new SocialAuth(), 'completeSuccessfulAuth', [$user, 'login', 'ok']));
        $payload = $completion['payload'];

        $this->assertKeySet(self::CHALLENGE_KEYS, $payload);
        $this->assertTrue($payload['two_factor_required']);
        $this->assertSame(['totp'], $payload['available_methods']);
        $this->assertSame('login', $payload['action']);
        $this->assertSame('/diary', $payload['return_to']);
        $this->assertNotNull(TwoFactorChallenge::findValidToken($payload['challenge_token']));
        $this->assertSame((int) $user->id, (int) TwoFactorChallenge::findValidToken($payload['challenge_token'])->user_id);
    }

    public function test_oauth_login_for_a_2fa_user_defers_the_login_event(): void
    {
        $user = $this->twoFactorUser();
        $user->linkOAuthProvider('google', 'google-id-1', ['token' => 'tok', 'refreshToken' => null, 'expiresIn' => 3600]);

        $redirect = $this->invoke(new SocialAuth(), 'handleOAuthLogin', ['google', $this->socialiteUser($user->email)]);

        $this->assertKeySet(self::CHALLENGE_KEYS, $this->cachedCompletion($redirect)['payload']);
        $this->assertSame(0, $this->logins);
        $this->assertNull(UserModel::find($user->id)->last_ip_address);
    }

    public function test_oauth_login_without_2fa_fires_the_login_event(): void
    {
        $user = $this->makeUser();
        $user->linkOAuthProvider('google', 'google-id-2', ['token' => 'tok', 'refreshToken' => null, 'expiresIn' => 3600]);

        $redirect = $this->invoke(new SocialAuth(), 'handleOAuthLogin', ['google', $this->socialiteUser($user->email, 'google-id-2')]);

        $this->assertKeySet(self::LEGACY_KEYS, $this->cachedCompletion($redirect)['payload']);
        $this->assertSame(1, $this->logins);
    }

    // ---- ApiController::oauthComplete ---------------------------------------

    public function test_oauth_complete_passes_a_challenge_through(): void
    {
        $user = $this->twoFactorUser();
        $completion = $this->cachedCompletion($this->invoke(new SocialAuth(), 'completeSuccessfulAuth', [$user, 'login', 'ok']));

        [$status, $body] = $this->callJson(fn () => (new ApiController())->oauthComplete(
            Request::create('/_user/api/v1/oauth-complete', 'GET', ['code' => $completion['code']])
        ));

        $this->assertSame(200, $status);
        $this->assertKeySet(self::CHALLENGE_KEYS, $body);
        $this->assertSame($completion['payload']['challenge_token'], $body['challenge_token']);
    }

    public function test_oauth_complete_keeps_the_legacy_shape_without_2fa(): void
    {
        $user = $this->makeUser();
        $completion = $this->cachedCompletion($this->invoke(new SocialAuth(), 'completeSuccessfulAuth', [$user, 'login', 'ok']));

        [$status, $body] = $this->callJson(fn () => (new ApiController())->oauthComplete(
            Request::create('/_user/api/v1/oauth-complete', 'GET', ['code' => $completion['code']])
        ));

        $this->assertSame(200, $status);
        $this->assertKeySet(self::LEGACY_KEYS, $body);
        $this->assertNotEmpty($body['token']);
    }

    // ---- (2) buildAuthResultFromExistingUser / oauthRegisterComplete ---------

    public function test_existing_2fa_user_gets_a_challenge_and_no_login_event(): void
    {
        $user = $this->twoFactorUser();

        $result = $this->invoke(new SocialAuth(), 'buildAuthResultFromExistingUser', [$user, 'google', $this->pendingPayload($user->email), 'login']);

        $this->assertKeySet(self::CHALLENGE_KEYS, $result);
        $this->assertArrayNotHasKey('token', $result);
        $this->assertSame(0, $this->logins);
    }

    public function test_existing_user_without_2fa_gets_a_token_and_a_login_event(): void
    {
        $user = $this->makeUser();

        $result = $this->invoke(new SocialAuth(), 'buildAuthResultFromExistingUser', [$user, 'google', $this->pendingPayload($user->email), 'login']);

        $this->assertKeySet(self::LEGACY_KEYS, $result);
        $this->assertSame(1, $this->logins);
    }

    public function test_oauth_register_complete_passes_a_challenge_through(): void
    {
        $user = $this->twoFactorUser();
        $pendingCode = str_repeat('p', 64);
        Cache::put('oauth-pending-registration:' . $pendingCode, $this->pendingPayload($user->email), now()->addMinutes(5));

        [$status, $body] = $this->callJson(fn () => (new ApiController())->oauthRegisterComplete(
            Request::create('/_user/api/v1/oauth-register-complete', 'POST', [
                'pending_code' => $pendingCode,
                'terms_accepted' => true,
                'privacy_accepted' => true,
            ])
        ));

        $this->assertSame(200, $status, json_encode($body));
        $this->assertKeySet(self::CHALLENGE_KEYS, $body);
        $this->assertSame(0, $this->logins);
    }

    // ---- (3) account linking with only a Winter session ----------------------

    public function test_linking_with_only_a_session_is_refused_for_a_2fa_user(): void
    {
        $user = $this->twoFactorUser();
        Auth::login($user);

        $this->expectException(ApplicationException::class);
        $this->expectExceptionMessage(trans('golem15.user::lang.oauth.must_be_logged_in'));

        $this->invoke(new SocialAuth(), 'handleAccountLinking', ['google', $this->socialiteUser('linked@example.tld', 'google-link-1')]);
    }

    public function test_linking_with_only_a_session_proceeds_for_a_user_without_2fa(): void
    {
        $user = $this->makeUser();
        Auth::login($user);

        $redirect = $this->invoke(new SocialAuth(), 'handleAccountLinking', ['google', $this->socialiteUser('linked@example.tld', 'google-link-2')]);
        $payload = $this->cachedCompletion($redirect)['payload'];

        $this->assertKeySet(self::LEGACY_KEYS, $payload);
        $this->assertSame('link', $payload['action']);
        $this->assertTrue(UserModel::find($user->id)->hasOAuthProvider('google'));
    }

    // ---- D-03 core half: trusted-device completion ---------------------------

    public function test_trusted_device_completes_the_owners_challenge_once(): void
    {
        Settings::set('trusted_device_enabled', true);
        $user = $this->twoFactorUser();
        $service = $this->service();
        $device = $service->createTrustedDeviceToken($user);
        $challenge = $service->createChallenge($user);

        $result = $service->completeChallengeWithTrustedDevice($challenge->token, $device);

        $this->assertIsArray($result);
        $this->assertSame((int) $user->id, (int) $result['user']['id']);
        $this->assertNotEmpty($result['token']);
        $this->assertSame(1, $this->logins);

        $this->assertFalse($service->completeChallengeWithTrustedDevice($challenge->token, $device));
        $this->assertSame(1, $this->logins);
    }

    public function test_another_users_trusted_device_cannot_complete_a_challenge(): void
    {
        Settings::set('trusted_device_enabled', true);
        $user = $this->twoFactorUser();
        $other = $this->twoFactorUser();
        $service = $this->service();
        $foreignDevice = $service->createTrustedDeviceToken($other);

        $this->assertFalse($service->completeChallengeWithTrustedDevice($service->createChallenge($user)->token, $foreignDevice));
    }

    public function test_trusted_device_completion_is_off_when_the_feature_is_disabled(): void
    {
        Settings::set('trusted_device_enabled', true);
        $user = $this->twoFactorUser();
        $service = $this->service();
        $device = $service->createTrustedDeviceToken($user);
        Settings::set('trusted_device_enabled', false);

        $this->assertFalse($service->completeChallengeWithTrustedDevice($service->createChallenge($user)->token, $device));
    }

    // ---- D-13: enabling 2FA does not sign existing JWTs out ------------------

    public function test_a_jwt_minted_before_enabling_totp_still_refreshes(): void
    {
        $user = $this->makeUser();
        $token = $this->jwtFor($user);

        $secret = $this->google2fa->generateSecretKey();
        $this->assertTrue($this->service()->confirmTotp($user, $secret, $this->otpAt($secret, $this->currentTimestep())));

        [$status, $body] = $this->callJson(fn () => (new ApiController())->refresh($this->request([], $token)));

        $this->assertSame(200, $status, json_encode($body));
        $this->assertNotEmpty($body['token']);
        $this->assertNotSame($token, $body['token']);
    }
}
