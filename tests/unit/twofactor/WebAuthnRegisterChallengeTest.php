<?php

namespace Golem15\User\Tests\Unit\TwoFactor;

require_once __DIR__ . '/TwoFactorTestCase.php';

use Cache;
use Golem15\User\Controllers\TwoFactorApiController;
use Golem15\User\Models\WebAuthnCredential;

/**
 * D-26: POST /2fa/webauthn/register uses the challenge cached server-side by
 * /2fa/webauthn/register/options (one-time, 5 minutes) and ignores whatever
 * challenge the client sends.
 */
class WebAuthnRegisterChallengeTest extends TwoFactorTestCase
{
    public function setUp(): void
    {
        parent::setUp();
        $this->enableTwoFactorSettings();
        $this->configureWebAuthn();
    }

    private function registerOptions($user): array
    {
        $jwt = $this->jwtFor($user);

        return $this->callJson(fn () => (new TwoFactorApiController())->webauthnRegisterOptions($this->request([], $jwt)));
    }

    private function register($user, array $attestation, ?string $clientChallenge): array
    {
        $jwt = $this->jwtFor($user);
        $body = ['attestation' => $attestation, 'name' => 'Desk key'];
        if ($clientChallenge !== null) {
            $body['challenge'] = $clientChallenge;
        }

        return $this->callJson(fn () => (new TwoFactorApiController())->webauthnRegister($this->request($body, $jwt)));
    }

    public function test_options_cache_the_challenge_for_the_user(): void
    {
        $user = $this->makeUser();

        [$status, $body] = $this->registerOptions($user);

        $this->assertSame(200, $status);
        $this->assertArrayHasKey('challenge', $body); // response shape unchanged
        $this->assertSame($body['challenge'], Cache::get('2fa-webauthn-reg:' . $user->id));
    }

    public function test_register_ignores_a_forged_client_challenge(): void
    {
        $user = $this->makeUser();
        [, $options] = $this->registerOptions($user);
        $attestation = $this->softAuthenticator()->create(base64_decode($options['challenge']));

        [$status, $body] = $this->register($user, $attestation, base64_encode(random_bytes(32)));

        $this->assertSame(200, $status, json_encode($body));
        $this->assertSame(1, WebAuthnCredential::where('user_id', $user->id)->count());
    }

    public function test_register_works_without_a_client_challenge(): void
    {
        $user = $this->makeUser();
        [, $options] = $this->registerOptions($user);
        $attestation = $this->softAuthenticator()->create(base64_decode($options['challenge']));

        [$status] = $this->register($user, $attestation, null);

        $this->assertSame(200, $status);
    }

    public function test_cached_challenge_is_one_time(): void
    {
        $user = $this->makeUser();
        [, $options] = $this->registerOptions($user);
        $challengeBin = base64_decode($options['challenge']);

        [$first] = $this->register($user, $this->softAuthenticator()->create($challengeBin), $options['challenge']);
        $this->assertSame(200, $first);

        [$status, $body] = $this->register($user, $this->softAuthenticator()->create($challengeBin), $options['challenge']);
        $this->assertSame(422, $status);
        $this->assertSame('Registration expired. Request new registration options.', $body['error']);
        $this->assertSame(1, WebAuthnCredential::where('user_id', $user->id)->count());
    }

    public function test_register_without_prior_options_is_rejected(): void
    {
        $user = $this->makeUser();
        $challenge = random_bytes(32);

        [$status, $body] = $this->register($user, $this->softAuthenticator()->create($challenge), base64_encode($challenge));

        $this->assertSame(422, $status);
        $this->assertSame('Registration expired. Request new registration options.', $body['error']);
        $this->assertSame(0, WebAuthnCredential::where('user_id', $user->id)->count());
    }
}
