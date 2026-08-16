<?php

namespace Golem15\User\Tests\Unit\Components;

use Config;
use ReflectionMethod;
use Illuminate\Http\Request;
use Illuminate\Contracts\Encryption\Encrypter;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use Golem15\User\Components\SocialAuth;
use Golem15\User\Models\User as UserModel;
use Golem15\User\Tests\UserPluginTestCase;
use Winter\Storm\Cookie\Middleware\EncryptCookies;

/**
 * Regression: Settings → Connect Google/Facebook (action=link) authenticates
 * from a JS-set JWT cookie. Winter EncryptCookies nulls plaintext cookies that
 * are not in cookie.unencryptedCookies, so resolveAuthenticatedUser() used to
 * throw "You must be logged in to link an OAuth account."
 *
 * Plugin routes are not registered in this harness — the production failure
 * is the cookie bag after EncryptCookies, which this suite drives directly.
 *
 * @group registration
 */
class OAuthLinkCookieTest extends UserPluginTestCase
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

    protected function makeUser(string $email): UserModel
    {
        $user = new UserModel();
        $user->fill([
            'name' => 'Link Tester',
            'email' => $email,
            'password' => 'originalpass1',
            'password_confirmation' => 'originalpass1',
        ]);
        $user->is_activated = true;
        $user->forceSave();

        return $user->fresh();
    }

    protected function invokeResolve(SocialAuth $component): ?UserModel
    {
        $ref = new ReflectionMethod(SocialAuth::class, 'resolveAuthenticatedUser');
        $ref->setAccessible(true);

        return $ref->invoke($component);
    }

    /**
     * Run Winter EncryptCookies over $request (using current
     * cookie.unencryptedCookies) then resolveAuthenticatedUser() against the
     * decrypted cookie bag — the same order as GET /oauth/{provider}.
     */
    protected function resolveAfterEncryptCookies(Request $request): ?UserModel
    {
        $resolved = null;
        $middleware = new EncryptCookies($this->app->make(Encrypter::class));
        $middleware->handle($request, function ($req) use (&$resolved) {
            $this->app->instance('request', $req);
            JWTAuth::setRequest($req);
            $resolved = $this->invokeResolve(new SocialAuth());

            return response('ok');
        });

        return $resolved;
    }

    public function test_plaintext_auth_token_is_nulled_when_not_excepted(): void
    {
        Config::set('cookie.unencryptedCookies', []);

        $user = $this->makeUser('link-nulled@example.tld');
        $request = Request::create('/oauth/google', 'GET', ['action' => 'link']);
        $request->cookies->set('auth_token', JWTAuth::fromUser($user));

        $this->assertNull($this->resolveAfterEncryptCookies($request));
    }

    public function test_plaintext_auth_token_survives_and_resolves_user(): void
    {
        Config::set('cookie.unencryptedCookies', ['token', 'auth_token']);

        $user = $this->makeUser('link-auth-token@example.tld');
        $request = Request::create('/oauth/google', 'GET', ['action' => 'link']);
        $request->cookies->set('auth_token', JWTAuth::fromUser($user));

        $resolved = $this->resolveAfterEncryptCookies($request);
        $this->assertNotNull($resolved);
        $this->assertSame($user->id, $resolved->id);
    }

    public function test_plaintext_token_mirror_survives_and_resolves_user(): void
    {
        Config::set('cookie.unencryptedCookies', ['token', 'auth_token']);

        $user = $this->makeUser('link-token-mirror@example.tld');
        $request = Request::create('/oauth/google', 'GET', ['action' => 'link']);
        $request->cookies->set('token', JWTAuth::fromUser($user));

        $resolved = $this->resolveAfterEncryptCookies($request);
        $this->assertNotNull($resolved);
        $this->assertSame($user->id, $resolved->id);
    }

    public function test_link_without_jwt_cookie_resolves_nobody(): void
    {
        Config::set('cookie.unencryptedCookies', ['token', 'auth_token']);

        $request = Request::create('/oauth/google', 'GET', ['action' => 'link']);
        $this->assertNull($this->resolveAfterEncryptCookies($request));
    }
}
