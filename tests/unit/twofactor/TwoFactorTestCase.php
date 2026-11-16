<?php

namespace Golem15\User\Tests\Unit\TwoFactor;

use Carbon\Carbon;
use Config;
use Golem15\User\Classes\TwoFactor\TwoFactorService;
use Golem15\User\Models\Settings;
use Golem15\User\Models\TwoFactorMethod;
use Golem15\User\Models\User as UserModel;
use Golem15\User\Tests\UserPluginTestCase;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use PragmaRX\Google2FA\Google2FA;

require_once __DIR__ . '/SoftAuthenticator.php';

/**
 * Shared base for the phase 106.1 two-factor tests.
 *
 * PHPUnit only collects *Test.php, so this file (and SoftAuthenticator.php) are
 * pulled in with require_once by the test classes. Controllers are invoked
 * directly with a built Request: plugin routes are not registered under the
 * plain phpunit harness (same approach as JwtAuthorizeFailureTest).
 */
abstract class TwoFactorTestCase extends UserPluginTestCase
{
    protected Google2FA $google2fa;

    public function setUp(): void
    {
        parent::setUp();

        // Settings::resetDefault() (parent) only drops the static Settings
        // instance when a settings row still exists. After the previous test's
        // rollback there is none, so Settings::set() values from an earlier test
        // class would leak in. Start every 2FA test from the defaults.
        \System\Behaviors\SettingsModel::clearInternalCache();

        if (!Config::get('jwt.secret')) {
            Config::set('jwt.secret', 'testing-only-deterministic-jwt-secret-key-0001');
        }
        Config::set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'users']);
        Config::set('auth.providers.users', ['driver' => 'eloquent', 'model' => UserModel::class]);

        $this->google2fa = new Google2FA();
    }

    public function tearDown(): void
    {
        Carbon::setTestNow();
        parent::tearDown();
    }

    protected function enableTwoFactorSettings(array $overrides = []): void
    {
        Settings::set(array_merge([
            'two_factor_mode' => Settings::TWO_FACTOR_OPTIONAL,
            'two_factor_available_methods' => ['totp', 'webauthn'],
        ], $overrides));
    }

    protected function service(): TwoFactorService
    {
        // Rebuilt on every call: WebAuthnMethod builds its lbuchs instance from
        // config in the constructor, so a config change needs a fresh service.
        app()->forgetInstance(TwoFactorService::class);

        return app(TwoFactorService::class);
    }

    /**
     * lbuchs accepts an http origin only for rpId "localhost".
     */
    protected function softAuthenticator(string $rpId = 'localhost', string $origin = 'http://localhost'): SoftAuthenticator
    {
        return new SoftAuthenticator($rpId, $origin);
    }

    /**
     * Point WebAuthn at a fixed origin and policy, then rebuild the service
     * (the lbuchs instance reads config in its constructor).
     */
    protected function configureWebAuthn(array $userConfig = [], string $appUrl = 'http://localhost', string $appName = 'Golem15 Test'): void
    {
        Config::set('app.url', $appUrl);
        Config::set('app.name', $appName);
        Config::set('golem15.user::webAuthnRpId', $userConfig['webAuthnRpId'] ?? null);
        Config::set('golem15.user::webAuthnUserVerification', $userConfig['webAuthnUserVerification'] ?? 'preferred');
        Config::set('golem15.user::webAuthnResidentKey', $userConfig['webAuthnResidentKey'] ?? null);
    }

    /**
     * Register a SoftAuthenticator credential through TwoFactorService exactly as
     * the API does: options first, then the attestation built over that challenge.
     */
    protected function registerSoftKey(UserModel $user, SoftAuthenticator $soft, bool $uv = true, ?string $name = null)
    {
        $service = $this->service();
        $options = $service->getWebAuthnRegistrationOptions($user);

        return $service->registerWebAuthn($user, $soft->create(base64_decode($options['challenge']), $uv), $options['challenge'], $name);
    }

    protected function jwtFor(UserModel $user): string
    {
        return \PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth::fromUser($user);
    }

    protected function makeUser(array $attrs = []): UserModel
    {
        static $seq = 0;
        $seq++;

        $user = new UserModel();
        $user->fill(array_merge([
            'name' => 'Ewa',
            'surname' => 'Zielinska',
            'email' => "twofactor.user{$seq}@example.tld",
            'password' => 'originalpass1',
            'password_confirmation' => 'originalpass1',
        ], $attrs));
        $user->is_activated = true;
        $user->activated_at = Carbon::now();
        $user->forceSave();

        return $user->fresh();
    }

    /**
     * Create the enabled TOTP method row for a user and return the plaintext secret.
     */
    protected function enableTotpFor(UserModel $user): string
    {
        $secret = $this->google2fa->generateSecretKey();

        TwoFactorMethod::create([
            'user_id' => $user->id,
            'method' => TwoFactorMethod::METHOD_TOTP,
            'is_enabled' => true,
            'secret' => $secret,
        ]);

        return $secret;
    }

    protected function otpAt(string $secret, int $timestep): string
    {
        return $this->google2fa->oathTotp($secret, $timestep);
    }

    protected function currentTimestep(): int
    {
        return (int) floor(time() / 30);
    }

    /**
     * A six-digit code that is NOT valid for the secret anywhere in the window.
     */
    protected function wrongCodeFor(string $secret): string
    {
        $ts = $this->currentTimestep();
        $valid = [];
        for ($i = $ts - 2; $i <= $ts + 2; $i++) {
            $valid[] = $this->otpAt($secret, $i);
        }

        $candidate = 0;
        while (in_array(str_pad((string) $candidate, 6, '0', STR_PAD_LEFT), $valid, true)) {
            $candidate++;
        }

        return str_pad((string) $candidate, 6, '0', STR_PAD_LEFT);
    }

    /**
     * Run a controller call and return [status, decoded body].
     *
     * @return array{0: int, 1: array}
     */
    protected function callJson(callable $controllerCall): array
    {
        $this->app->forgetInstance('tymon.jwt');
        $this->app->forgetInstance('tymon.jwt.parser');

        /** @var JsonResponse $response */
        $response = $controllerCall();

        return [$response->getStatusCode(), $response->getData(true)];
    }

    protected function request(array $body, ?string $bearer = null, string $method = 'POST'): Request
    {
        $request = Request::create('/_user/api/v1/2fa', $method, $body);
        if ($bearer !== null) {
            $request->headers->set('Authorization', 'Bearer ' . $bearer);
        }

        return $request;
    }
}
