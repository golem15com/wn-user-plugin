<?php

namespace Golem15\User\Tests\Unit\DeviceFlow;

require_once __DIR__ . '/../twofactor/TwoFactorTestCase.php';

use Golem15\User\Controllers\ApiController;
use Golem15\User\Controllers\DeviceFlowApiController;
use Golem15\User\Models\DeviceAuthSession;
use Golem15\User\Models\User as UserModel;
use Golem15\User\Tests\Unit\TwoFactor\TwoFactorTestCase;
use Illuminate\Http\Request;

/**
 * Shared base for the phase 107.1 device-flow redeem tests.
 *
 * Controllers are invoked directly with a built Request (plugin routes are not
 * registered under the plain phpunit harness), exactly as the 2FA tests do.
 */
abstract class DeviceFlowTestCase extends TwoFactorTestCase
{
    /** RFC 7636 Appendix B test vector. */
    public const RFC_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    public const RFC_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /**
     * A fresh PKCE pair: 32 random bytes base64url (43 chars) and its S256 challenge.
     *
     * @return array{0: string, 1: string} [verifier, challenge]
     */
    protected function pkcePair(): array
    {
        $verifier = $this->b64url(random_bytes(32));

        return [$verifier, $this->b64url(hash('sha256', $verifier, true))];
    }

    protected function b64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * @return array{0: int, 1: array}
     */
    protected function initiate(array $body = [], ?string $userAgent = null): array
    {
        $request = $this->request($body);
        if ($userAgent !== null) {
            $request->headers->set('User-Agent', $userAgent);
        }

        return $this->callJson(fn () => (new ApiController())->initiateDeviceAuth($request));
    }

    /**
     * Initiate a redeemable session and return [token, verifier, initiate body].
     *
     * @return array{0: string, 1: string, 2: array}
     */
    protected function initiateRedeemable(array $body = [], ?string $userAgent = null): array
    {
        [$verifier, $challenge] = $this->pkcePair();
        [$status, $resp] = $this->initiate(array_merge(['code_challenge' => $challenge, 'code_challenge_method' => 'S256'], $body), $userAgent);
        $this->assertSame(200, $status, json_encode($resp));

        return [$resp['data']['token'], $verifier, $resp];
    }

    /**
     * Confirm through the existing POST devices/authorize with the user's JWT.
     *
     * @return array{0: int, 1: array}
     */
    protected function confirmAs(UserModel $user, string $token): array
    {
        $jwt = $this->jwtFor($user);

        return $this->callJson(fn () => (new ApiController())->authorizeDevice($this->request(['token' => $token], $jwt)));
    }

    /**
     * @return array{0: int, 1: array}
     */
    protected function authorizeShortCodeAs(UserModel $user, string $shortCode): array
    {
        $jwt = $this->jwtFor($user);

        return $this->callJson(fn () => (new ApiController())->authorizeDevice($this->request(['short_code' => $shortCode], $jwt)));
    }

    /**
     * @return array{0: int, 1: array}
     */
    protected function poll(string $token, ?string $verifier): array
    {
        return $this->callJson(fn () => (new DeviceFlowApiController())->poll($this->request($this->grantBody($token, $verifier))));
    }

    /**
     * @return array{0: int, 1: array}
     */
    protected function redeem(string $token, ?string $verifier): array
    {
        return $this->callJson(fn () => (new DeviceFlowApiController())->redeem($this->request($this->grantBody($token, $verifier))));
    }

    /**
     * @return array{0: int, 1: array}
     */
    protected function describe(string $token, ?UserModel $as): array
    {
        $jwt = $as ? $this->jwtFor($as) : null;

        return $this->callJson(fn () => (new DeviceFlowApiController())->describe($this->request(['token' => $token], $jwt)));
    }

    /**
     * @return array{0: int, 1: array}
     */
    protected function deny(string $token, ?UserModel $as): array
    {
        $jwt = $as ? $this->jwtFor($as) : null;

        return $this->callJson(fn () => (new DeviceFlowApiController())->deny($this->request(['token' => $token], $jwt)));
    }

    protected function deviceSession(string $token): DeviceAuthSession
    {
        return DeviceAuthSession::where('token', $token)->firstOrFail();
    }

    protected function grantBody(string $token, ?string $verifier): array
    {
        $body = ['token' => $token];
        if ($verifier !== null) {
            $body['code_verifier'] = $verifier;
        }

        return $body;
    }

    protected function request(array $body, ?string $bearer = null, string $method = 'POST'): Request
    {
        $request = Request::create('/_user/api/v1/devices', $method, $body);
        if ($bearer !== null) {
            $request->headers->set('Authorization', 'Bearer ' . $bearer);
        }

        return $request;
    }
}
