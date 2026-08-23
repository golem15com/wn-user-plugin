<?php

namespace Golem15\User\Tests\Unit\Controllers;

use Carbon\Carbon;
use Config;
use Illuminate\Http\Request;
use Golem15\User\Controllers\ApiController;
use Golem15\User\Models\User as UserModel;
use Golem15\User\Tests\UserPluginTestCase;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

/**
 * Regression lock: ApiController::authorize() must normalise every JWT failure
 * mode into a 401, never let a raw JWTException escape.
 *
 * Before the fix, authorize() called JWTAuth::toUser() with no try/catch. The
 * callers catch AuthenticationException|TokenBlacklistedException, but
 * TokenExpiredException is a SIBLING of TokenBlacklistedException (both extend
 * JWTException), not a subclass -- so an expired token, the single most routine
 * outcome there is, escaped uncaught. Winter's handler logged the full stack
 * trace to system.log and returned 500. Clients that only refresh on 401 then
 * never recovered and kept resending the dead token, so the log filled up.
 *
 * Invokes the controller method directly with a built Request: plugin routes
 * are not registered under the plain phpunit harness.
 */
class JwtAuthorizeFailureTest extends UserPluginTestCase
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

    public function tearDown(): void
    {
        Carbon::setTestNow();
        parent::tearDown();
    }

    protected function makeUser(array $overrides = []): UserModel
    {
        $user = new UserModel();
        $user->fill(array_merge([
            'name' => 'Ewa',
            'surname' => 'Zielinska',
            'email' => 'ewa.zielinska@example.tld',
            'password' => 'originalpass1',
            'password_confirmation' => 'originalpass1',
        ], $overrides));
        $user->forceSave();

        return $user->fresh();
    }

    protected function fetchWithToken(?string $token): \Illuminate\Http\JsonResponse
    {
        $this->app->forgetInstance('tymon.jwt');
        $this->app->forgetInstance('tymon.jwt.parser');

        $request = Request::create('/_user/api/v1/fetch', 'GET');
        if ($token !== null) {
            $request->headers->set('Authorization', 'Bearer ' . $token);
        }

        return (new ApiController())->fetch($request);
    }

    /**
     * The reported bug: an expired token produced an unhandled 500 plus a
     * stack trace in system.log instead of a clean 401.
     */
    public function test_fetch_with_expired_token_returns_401(): void
    {
        $user = $this->makeUser();
        $token = JWTAuth::fromUser($user);

        // Travel past the access TTL. jwt-auth reads the clock through
        // Support\Utils::now() -> Carbon::now('UTC'), so setTestNow() ages the
        // token without having to forge one (the factory validates on create).
        $ttlMinutes = (int) (Config::get('jwt.ttl') ?: 60);
        Carbon::setTestNow(Carbon::now()->addMinutes($ttlMinutes + 10));

        $response = $this->fetchWithToken($token);

        $this->assertSame(401, $response->getStatusCode());
        $this->assertTrue($response->getData(true)['error']);
    }

    public function test_fetch_with_malformed_token_returns_401(): void
    {
        $response = $this->fetchWithToken('not.a.valid.jwt');

        $this->assertSame(401, $response->getStatusCode());
    }

    /**
     * JWTAuth::toUser() returns JWTSubject|false -- false when the `sub` claim
     * no longer resolves to a user row. Without an explicit guard that false
     * hits authorize()'s `: UserModel` return type and raises a TypeError,
     * i.e. another unhandled 500.
     */
    public function test_fetch_with_token_for_deleted_user_returns_401(): void
    {
        $user = $this->makeUser(['email' => 'gone@example.tld']);
        $token = JWTAuth::fromUser($user);
        $user->forceDelete();

        $response = $this->fetchWithToken($token);

        $this->assertSame(401, $response->getStatusCode());
    }

    public function test_fetch_without_token_returns_401(): void
    {
        $response = $this->fetchWithToken(null);

        $this->assertSame(401, $response->getStatusCode());
    }

    /**
     * The happy path must be untouched by the normalisation.
     */
    public function test_fetch_with_valid_token_returns_user(): void
    {
        $user = $this->makeUser(['email' => 'valid@example.tld']);

        $response = $this->fetchWithToken(JWTAuth::fromUser($user));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('valid@example.tld', $response->getData(true)['user']['email']);
    }
}
