<?php

namespace Golem15\User\Tests\Unit\TwoFactor;

require_once __DIR__ . '/TwoFactorTestCase.php';

use Auth;
use Cache;
use Event;
use Golem15\User\Classes\TwoFactor\WebAuthnMethod;
use Golem15\User\Controllers\TwoFactorApiController;
use Golem15\User\Models\TwoFactorChallenge;
use Golem15\User\Models\User as UserModel;
use Golem15\User\Models\WebAuthnCredential;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

/**
 * D-04 / D-06a: "Sign in with passkey" through a session-less JWT API.
 *
 * POST /2fa/passwordless/options hands out a one-time handle for a server-held
 * challenge; POST /2fa/passwordless/verify answers it with a discoverable
 * credential assertion and mints a JWT for the credential's owner. Off by
 * default, and every mismatch gets the same generic 401.
 */
class PasswordlessApiTest extends TwoFactorTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        $this->configureWebAuthn();
    }

    protected function enablePasswordless(array $overrides = []): void
    {
        $this->enableTwoFactorSettings(array_merge(['two_factor_passwordless_login' => true], $overrides));
    }

    protected function controller(): TwoFactorApiController
    {
        // The controller resolves TwoFactorService in its constructor; drop any
        // cached instance so the current config reaches the lbuchs instance.
        $this->service();
        app()->forgetInstance(\Golem15\User\Classes\TwoFactor\TwoFactorService::class);

        return new TwoFactorApiController();
    }

    /**
     * @return array{0: int, 1: array}
     */
    protected function requestOptions(): array
    {
        return $this->callJson(fn () => $this->controller()->passwordlessOptions($this->request([])));
    }

    /**
     * @return array{0: int, 1: array}
     */
    protected function verifyWith(string $handle, array $assertion): array
    {
        return $this->callJson(fn () => $this->controller()->passwordlessVerify(
            $this->request(['handle' => $handle, 'assertion' => $assertion])
        ));
    }

    /**
     * Options, then an assertion built by $soft over the server-held challenge.
     *
     * @return array{handle: string, assertion: array}
     */
    protected function signedAssertion(SoftAuthenticator $soft, ?string $userHandleBin, bool $uv = true, int $signCount = 1): array
    {
        [$status, $body] = $this->requestOptions();
        $this->assertSame(200, $status);

        $challenge = Cache::get('2fa-passwordless:' . $body['handle']);
        $this->assertIsString($challenge);

        return [
            'handle' => $body['handle'],
            'assertion' => $soft->get(base64_decode($challenge), $uv, $userHandleBin, $signCount),
        ];
    }

    /**
     * @return array{0: UserModel, 1: SoftAuthenticator}
     */
    protected function ownerWithPasskey(bool $uv = true): array
    {
        $owner = $this->makeUser();
        $soft = $this->softAuthenticator();
        $this->registerSoftKey($owner, $soft, $uv);

        return [$owner, $soft];
    }

    protected function handleFor(int $userId): string
    {
        return (new WebAuthnMethod())->userHandleFor($userId);
    }

    protected function assertGenericFailure(array $result): void
    {
        [$status, $body] = $result;
        $this->assertSame(401, $status);
        $this->assertTrue($body['passkey_failed']);
        $this->assertSame('Passkey sign-in failed.', $body['error']);
        $this->assertArrayNotHasKey('token', $body);
    }

    // ---- (1) off by default -------------------------------------------------

    public function test_default_settings_refuse_options_and_verify(): void
    {
        $this->enableTwoFactorSettings();

        [$status] = $this->requestOptions();
        $this->assertSame(403, $status);

        [$status] = $this->verifyWith(str_repeat('a', 64), ['id' => 'x']);
        $this->assertSame(403, $status);
    }

    public function test_passwordless_on_but_webauthn_unavailable_is_refused(): void
    {
        $this->enablePasswordless(['two_factor_available_methods' => ['totp']]);

        [$status] = $this->requestOptions();
        $this->assertSame(403, $status);
    }

    // ---- (2) happy path -----------------------------------------------------

    public function test_options_return_a_handle_and_a_challenge(): void
    {
        $this->enablePasswordless();

        [$status, $body] = $this->requestOptions();

        $this->assertSame(200, $status);
        $this->assertSame(64, strlen($body['handle']));
        $this->assertNotEmpty($body['options']['publicKey']['challenge']);
        $this->assertSame([], $body['options']['publicKey']['allowCredentials'] ?? []);
    }

    public function test_verify_signs_the_owner_in_with_a_jwt(): void
    {
        $this->enablePasswordless();
        [$owner, $soft] = $this->ownerWithPasskey();

        $logins = 0;
        Event::listen('golem15.user.login', function () use (&$logins) {
            $logins++;
        });

        $signed = $this->signedAssertion($soft, $this->handleFor($owner->id));
        [$status, $body] = $this->verifyWith($signed['handle'], $signed['assertion']);

        $this->assertSame(200, $status);
        $this->assertSame((int) $owner->id, (int) $body['user']['id']);
        $this->assertSame((string) $owner->id, (string) JWTAuth::setToken($body['token'])->getPayload()->get('sub'));
        $this->assertSame(1, $logins);
    }

    // ---- (3) replay ---------------------------------------------------------

    public function test_a_handle_can_be_answered_once(): void
    {
        $this->enablePasswordless();
        [$owner, $soft] = $this->ownerWithPasskey();

        $signed = $this->signedAssertion($soft, $this->handleFor($owner->id));
        [$status] = $this->verifyWith($signed['handle'], $signed['assertion']);
        $this->assertSame(200, $status);

        $this->assertGenericFailure($this->verifyWith($signed['handle'], $signed['assertion']));
    }

    public function test_an_unknown_handle_is_refused(): void
    {
        $this->enablePasswordless();
        [$owner, $soft] = $this->ownerWithPasskey();

        $signed = $this->signedAssertion($soft, $this->handleFor($owner->id));

        $this->assertGenericFailure($this->verifyWith(str_repeat('z', 64), $signed['assertion']));
    }

    // ---- (4) userHandle -----------------------------------------------------

    public function test_a_user_handle_of_another_user_is_refused(): void
    {
        $this->enablePasswordless();
        [$owner, $soft] = $this->ownerWithPasskey();
        $other = $this->makeUser();

        $signed = $this->signedAssertion($soft, $this->handleFor($other->id));

        $this->assertGenericFailure($this->verifyWith($signed['handle'], $signed['assertion']));
    }

    public function test_a_missing_user_handle_is_rejected_by_validation(): void
    {
        $this->enablePasswordless();
        [, $soft] = $this->ownerWithPasskey();

        $signed = $this->signedAssertion($soft, null);
        [$status, $body] = $this->verifyWith($signed['handle'], $signed['assertion']);

        $this->assertSame(422, $status);
        $this->assertArrayHasKey('assertion.response.userHandle', $body['errors']);
    }

    // ---- (5) banned / (6) unactivated ---------------------------------------

    public function test_a_banned_owner_is_refused(): void
    {
        $this->enablePasswordless();
        [$owner, $soft] = $this->ownerWithPasskey();
        Auth::findThrottleByUserId($owner->id)->ban();

        $signed = $this->signedAssertion($soft, $this->handleFor($owner->id));

        $this->assertGenericFailure($this->verifyWith($signed['handle'], $signed['assertion']));
    }

    public function test_an_unactivated_owner_is_refused(): void
    {
        $this->enablePasswordless();
        [$owner, $soft] = $this->ownerWithPasskey();
        $owner->is_activated = false;
        $owner->forceSave();

        $signed = $this->signedAssertion($soft, $this->handleFor($owner->id));

        $this->assertGenericFailure($this->verifyWith($signed['handle'], $signed['assertion']));
    }

    // ---- (7) user verification ----------------------------------------------

    public function test_required_user_verification_refuses_an_assertion_without_uv(): void
    {
        $this->configureWebAuthn(['webAuthnUserVerification' => 'required']);
        $this->enablePasswordless();
        [$owner, $soft] = $this->ownerWithPasskey(true);

        $signed = $this->signedAssertion($soft, $this->handleFor($owner->id), false);
        $this->assertGenericFailure($this->verifyWith($signed['handle'], $signed['assertion']));

        $signed = $this->signedAssertion($soft, $this->handleFor($owner->id), true, 2);
        [$status] = $this->verifyWith($signed['handle'], $signed['assertion']);
        $this->assertSame(200, $status);
    }

    // ---- (8) disabled credential --------------------------------------------

    public function test_a_disabled_credential_is_refused(): void
    {
        $this->enablePasswordless();
        [$owner, $soft] = $this->ownerWithPasskey();
        WebAuthnCredential::where('user_id', $owner->id)->update(['is_enabled' => false]);

        $signed = $this->signedAssertion($soft, $this->handleFor($owner->id));

        $this->assertGenericFailure($this->verifyWith($signed['handle'], $signed['assertion']));
    }

    // ---- (9) complete sign-in, no challenge row -----------------------------

    public function test_success_creates_no_two_factor_challenge(): void
    {
        $this->enablePasswordless();
        [$owner, $soft] = $this->ownerWithPasskey();
        $before = TwoFactorChallenge::where('user_id', $owner->id)->count();

        $signed = $this->signedAssertion($soft, $this->handleFor($owner->id));
        [$status, $body] = $this->verifyWith($signed['handle'], $signed['assertion']);

        $this->assertSame(200, $status);
        $this->assertSame(['token', 'user'], array_keys($body));
        $this->assertSame($before, TwoFactorChallenge::where('user_id', $owner->id)->count());
    }
}
