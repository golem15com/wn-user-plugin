<?php namespace Golem15\User\Tests\Security;

use ApplicationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Lang;
use Golem15\User\Components\SocialAuth;
use Golem15\User\Controllers\ApiController;
use Golem15\User\Models\User as UserModel;
use Golem15\User\Tests\UserPluginTestCase;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

/**
 * k7ut351s — an account created through Google/Facebook OAuth registration has
 * `password` filled with Str::random(16) at registration time
 * (SocialAuth.php ~527 / ~1033), so ApiController::changePassword()'s
 * Hash::check() against that placeholder hash can never pass: the account has
 * NO route to a self-chosen password anywhere in the product. The same root
 * cause left the "prevent lockout" guard in SocialAuth::onUnlinkOAuth() dead —
 * it tested empty($user->password), which is never true for an OAuth account,
 * so unlinking the last identity from a password-less account was silently
 * allowed and would strand the holder with no way to sign back in.
 *
 * These tests lock BOTH halves of the fix (14-01-PLAN.md Task 2):
 *  1. An account with has_self_set_password === false may change its password
 *     WITHOUT current_password.
 *  2. An account with a real, self-set password is BYTE-IDENTICAL to today:
 *     current_password is still required and still checked (proof: 422s, not
 *     a declaration).
 *  3. The unlink guard actually fires for a password-less account unlinking
 *     its LAST identity, and does not fire for the safe cases (a non-last
 *     identity on the same account, or any identity on a real-password
 *     account).
 *  4. The relaxation is one-shot: the first successful password write disarms
 *     the flag, closing the window.
 *  5. OAuth registration marks brand-new accounts has_self_set_password=false
 *     from the first second they exist (does not rely solely on the v3.4.0
 *     migration backfill).
 *
 * @group security
 */
class OAuthPasswordBootstrapTest extends UserPluginTestCase
{
    public function setUp(): void
    {
        parent::setUp();

        if (!Config::get('jwt.secret')) {
            Config::set('jwt.secret', 'testing-only-deterministic-jwt-secret-key-0001');
        }
        Config::set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'users']);
        Config::set('auth.providers.users', ['driver' => 'eloquent', 'model' => UserModel::class]);
    }

    /**
     * @param array $overrides
     * @param bool  $hasSelfSetPassword Written the same way the production code paths write
     *                                  it: direct property assignment, never through $fillable
     *                                  (see User::$fillable / User::$casts, Task 1).
     */
    protected function makeUser(array $overrides, bool $hasSelfSetPassword): UserModel
    {
        $user = new UserModel();
        $user->fill(array_merge([
            'name' => 'Bootstrap Tester',
            'email' => 'bootstrap-' . uniqid() . '@example.tld',
            'password' => 'placeholder-not-asserted-1',
            'password_confirmation' => 'placeholder-not-asserted-1',
        ], $overrides));
        $user->is_activated = true;
        $user->has_self_set_password = $hasSelfSetPassword;
        $user->forceSave();

        return $user->fresh();
    }

    protected function linkOAuth(UserModel $user, string $provider = 'google', ?string $providerId = null): void
    {
        $user->linkOAuthProvider($provider, $providerId ?? ('id-' . uniqid()), ['token' => 'tok'], []);
    }

    /**
     * Bind $user as the authenticated caller of the current request container.
     * Both JWT-guard paths this file exercises read from here:
     * ApiController::authorize() via TokenExtractor::fromRequest($request), and
     * SocialAuth::resolveAuthenticatedUser() via JWTAuth::parseToken() against
     * the bound container request.
     */
    protected function authedRequest(UserModel $user, array $data = []): Request
    {
        $this->app->forgetInstance('tymon.jwt');
        $this->app->forgetInstance('tymon.jwt.parser');

        $request = Request::create('/_user/api/v1/change-password', 'POST', $data);
        $request->headers->set('Authorization', 'Bearer ' . JWTAuth::fromUser($user));

        $this->app->instance('request', $request);
        // The Request facade caches its first-resolved instance; without clearing
        // it here, SocialAuth's post('provider') keeps reading the stale GET
        // request from bootstrap instead of this test's rebound POST request.
        \Illuminate\Support\Facades\Request::clearResolvedInstance('request');
        JWTAuth::setRequest($request);

        return $request;
    }

    protected function unlinkAs(UserModel $user, string $provider): array
    {
        $this->authedRequest($user, ['provider' => $provider]);

        return (new SocialAuth())->onUnlinkOAuth();
    }

    protected function pendingPayload(array $overrides = []): array
    {
        return array_merge([
            'provider' => 'google',
            'provider_id' => 'new-oauth-id-' . uniqid(),
            'token' => 'tok',
            'refresh_token' => 'refresh',
            'expires_in' => 3600,
            'name' => 'Brand New OAuth User',
            'email' => 'new-oauth-' . uniqid() . '@example.tld',
            'avatar' => null,
            'return_to' => '/',
            'email_verified' => true,
            'reason' => null,
            'terms_accepted' => true,
            'privacy_accepted' => true,
            'marketing_consent' => false,
        ], $overrides);
    }

    // 1. Half one of k7ut351s: OAuth account sets a password without current_password.

    public function test_oauth_account_sets_password_without_current_password(): void
    {
        $user = $this->makeUser(['email' => 'oauth-half1@example.tld'], false);
        $this->linkOAuth($user, 'google');

        $response = (new ApiController())->changePassword($this->authedRequest($user, [
            'password' => 'BrandNewSecret1',
            'password_confirmation' => 'BrandNewSecret1',
        ]));

        $this->assertSame(200, $response->getStatusCode());

        $user = $user->fresh();
        $this->assertTrue(Hash::check('BrandNewSecret1', $user->password));
    }

    // 2. Dowód neutralności: a real-password account is byte-identical to today.

    public function test_real_password_account_still_requires_current_password(): void
    {
        $user = $this->makeUser([
            'email' => 'real-neutral@example.tld',
            'password' => 'OriginalSecret1',
            'password_confirmation' => 'OriginalSecret1',
        ], true);

        $missing = (new ApiController())->changePassword($this->authedRequest($user, [
            'password' => 'NewSecret2',
            'password_confirmation' => 'NewSecret2',
        ]));
        $this->assertSame(422, $missing->getStatusCode(), 'A real-password account must still require current_password.');

        $wrong = (new ApiController())->changePassword($this->authedRequest($user, [
            'current_password' => 'DefinitelyWrong',
            'password' => 'NewSecret2',
            'password_confirmation' => 'NewSecret2',
        ]));
        $this->assertSame(422, $wrong->getStatusCode());
        $this->assertSame(
            Lang::get('golem15.user::lang.account.invalid_login'),
            $wrong->getData(true)['error'],
            'The wrong-current-password error message must be unchanged.'
        );

        $user = $user->fresh();
        $this->assertTrue(Hash::check('OriginalSecret1', $user->password), 'Password must not have changed.');
    }

    // 3. The dead guard is alive — and only where it should be.

    public function test_unlink_guard_blocks_last_identity_on_password_less_account(): void
    {
        $user = $this->makeUser(['email' => 'oauth-guard@example.tld'], false);
        $this->linkOAuth($user, 'google', 'guard-single-1');

        $this->expectException(ApplicationException::class);
        // Pin the exact message, not just the exception class — a request-plumbing
        // bug that made hasOAuthProvider() see no linked provider at all would also
        // throw ApplicationException (the "no_provider_linked" branch, one line
        // above the real guard) and falsely look like a passing test.
        $this->expectExceptionMessage(Lang::get('golem15.user::lang.oauth.cannot_unlink_without_password'));

        try {
            $this->unlinkAs($user, 'google');
        } finally {
            $this->assertTrue(
                $user->fresh()->hasOAuthProvider('google'),
                'Last OAuth identity on a password-less account must survive a blocked unlink attempt.'
            );
        }
    }

    public function test_unlink_guard_allows_non_last_identity_on_password_less_account(): void
    {
        $user = $this->makeUser(['email' => 'oauth-guard-multi@example.tld'], false);
        $this->linkOAuth($user, 'google', 'guard-multi-google');
        $this->linkOAuth($user, 'facebook', 'guard-multi-facebook');

        $result = $this->unlinkAs($user, 'google');

        $this->assertSame(['success' => true], $result);
        $user = $user->fresh();
        $this->assertFalse($user->hasOAuthProvider('google'));
        $this->assertTrue($user->hasOAuthProvider('facebook'));
        $this->assertSame(1, $user->oauthIdentities()->count());
    }

    public function test_unlink_guard_allows_last_identity_on_real_password_account(): void
    {
        $user = $this->makeUser([
            'email' => 'real-guard@example.tld',
            'password' => 'RealSecret999',
            'password_confirmation' => 'RealSecret999',
        ], true);
        $this->linkOAuth($user, 'google', 'guard-real-google');

        $result = $this->unlinkAs($user, 'google');

        $this->assertSame(['success' => true], $result);
        $this->assertSame(0, $user->fresh()->oauthIdentities()->count());
    }

    // 4. Disarm: the relaxation window is one-shot.

    public function test_disarm_closes_the_no_current_password_window(): void
    {
        $user = $this->makeUser(['email' => 'oauth-disarm@example.tld'], false);
        $this->linkOAuth($user, 'google', 'disarm-1');

        $first = (new ApiController())->changePassword($this->authedRequest($user, [
            'password' => 'FirstSecret1',
            'password_confirmation' => 'FirstSecret1',
        ]));
        $this->assertSame(200, $first->getStatusCode());

        $user = $user->fresh();
        $this->assertTrue((bool) $user->has_self_set_password, 'A successful write must disarm the flag.');

        $second = (new ApiController())->changePassword($this->authedRequest($user, [
            'password' => 'SecondSecret2',
            'password_confirmation' => 'SecondSecret2',
        ]));
        $this->assertSame(
            422,
            $second->getStatusCode(),
            'The relaxation window must not survive a successful write — it is one-shot.'
        );
    }

    // 5. OAuth registration marks the new account from the first second it exists.

    public function test_oauth_registration_marks_new_account_password_less(): void
    {
        $result = (new SocialAuth())->completePendingRegistration($this->pendingPayload());

        $this->assertSame('register', $result['action']);
        $user = UserModel::find($result['user']['id']);
        $this->assertNotNull($user);
        $this->assertFalse((bool) $user->has_self_set_password);
    }
}
