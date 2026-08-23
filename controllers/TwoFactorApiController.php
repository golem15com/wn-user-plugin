<?php

namespace Golem15\User\Controllers;

use Golem15\User\Classes\TokenExtractor;
use Golem15\User\Classes\TwoFactor\TwoFactorService;
use Golem15\User\Models\TwoFactorChallenge;
use Golem15\User\Models\TwoFactorMethod;
use Golem15\User\Models\User as UserModel;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenBlacklistedException;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

class TwoFactorApiController
{
    protected TwoFactorService $service;

    public function __construct()
    {
        $this->service = app(TwoFactorService::class);
    }

    // ========================================================================
    // Challenge / Verification Endpoints (unauthenticated, during login flow)
    // ========================================================================

    /**
     * Verify a TOTP or email 2FA code.
     *
     * POST /_user/api/v1/2fa/verify
     * Body: { challenge_token, method: "totp"|"email", code: "123456" }
     */
    public function verify(Request $request): JsonResponse
    {
        $validation = Validator::make($request->all(), [
            'challenge_token' => 'required|string|size:64',
            'method' => 'required|string|in:totp,email',
            'code' => 'required|string|min:6|max:6',
        ]);

        if ($validation->fails()) {
            return response()->json([
                'error' => $validation->errors()->first(),
                'errors' => $validation->errors()->toArray(),
            ], 422);
        }

        $result = $this->service->verifyChallenge(
            $request->get('challenge_token'),
            $request->get('method'),
            $request->get('code')
        );

        if (!$result) {
            return response()->json([
                'error' => 'Invalid verification code.',
                'two_factor_failed' => true,
            ], 401);
        }

        return response()->json($this->withTrustedDevice($request, $result));
    }

    /**
     * Use a recovery code to bypass 2FA.
     *
     * POST /_user/api/v1/2fa/recovery
     * Body: { challenge_token, code: "XXXXX-XXXXX", trust_device? }
     */
    public function recovery(Request $request): JsonResponse
    {
        $validation = Validator::make($request->all(), [
            'challenge_token' => 'required|string|size:64',
            'code' => 'required|string',
        ]);

        if ($validation->fails()) {
            return response()->json([
                'error' => $validation->errors()->first(),
                'errors' => $validation->errors()->toArray(),
            ], 422);
        }

        $result = $this->service->verifyChallenge(
            $request->get('challenge_token'),
            'recovery',
            $request->get('code')
        );

        if (!$result) {
            return response()->json([
                'error' => 'Invalid recovery code.',
                'two_factor_failed' => true,
            ], 401);
        }

        return response()->json($this->withTrustedDevice($request, $result));
    }

    /**
     * Send an email 2FA code.
     *
     * POST /_user/api/v1/2fa/email/send
     * Body: { challenge_token }
     */
    public function sendEmailCode(Request $request): JsonResponse
    {
        $validation = Validator::make($request->all(), [
            'challenge_token' => 'required|string|size:64',
        ]);

        if ($validation->fails()) {
            return response()->json([
                'error' => $validation->errors()->first(),
            ], 422);
        }

        $challenge = TwoFactorChallenge::findValidToken($request->get('challenge_token'));
        if (!$challenge) {
            return response()->json(['error' => 'Invalid or expired challenge.'], 401);
        }

        $user = $challenge->user;
        if (!$user) {
            return response()->json(['error' => 'Invalid challenge.'], 401);
        }

        $maskedEmail = $this->service->sendEmailCode($challenge, $user);

        return response()->json([
            'message' => 'Verification code sent.',
            'email' => $maskedEmail,
        ]);
    }

    /**
     * Get WebAuthn assertion options for verification.
     *
     * POST /_user/api/v1/2fa/webauthn/options
     * Body: { challenge_token }
     */
    public function webauthnOptions(Request $request): JsonResponse
    {
        $validation = Validator::make($request->all(), [
            'challenge_token' => 'required|string|size:64',
        ]);

        if ($validation->fails()) {
            return response()->json([
                'error' => $validation->errors()->first(),
            ], 422);
        }

        $challenge = TwoFactorChallenge::findValidToken($request->get('challenge_token'));
        if (!$challenge) {
            return response()->json(['error' => 'Invalid or expired challenge.'], 401);
        }

        $user = $challenge->user;
        if (!$user) {
            return response()->json(['error' => 'Invalid challenge.'], 401);
        }

        $options = $this->service->getWebAuthnAuthenticationOptions($user);

        // Store the WebAuthn challenge on the 2FA challenge for later verification
        $challenge->method = TwoFactorMethod::METHOD_WEBAUTHN;
        $challenge->code = $options['challenge']; // base64-encoded, not hashed
        $challenge->save();

        return response()->json($options);
    }

    /**
     * Verify a WebAuthn assertion.
     *
     * POST /_user/api/v1/2fa/webauthn/verify
     * Body: { challenge_token, assertion: { id, response: { clientDataJSON, authenticatorData, signature } } }
     */
    public function webauthnVerify(Request $request): JsonResponse
    {
        $validation = Validator::make($request->all(), [
            'challenge_token' => 'required|string|size:64',
            'assertion' => 'required|array',
        ]);

        if ($validation->fails()) {
            return response()->json([
                'error' => $validation->errors()->first(),
                'errors' => $validation->errors()->toArray(),
            ], 422);
        }

        $challenge = TwoFactorChallenge::findValidToken($request->get('challenge_token'));
        if (!$challenge || !$challenge->code) {
            return response()->json(['error' => 'Invalid or expired challenge. Request WebAuthn options first.'], 401);
        }

        $result = $this->service->verifyChallenge(
            $request->get('challenge_token'),
            TwoFactorMethod::METHOD_WEBAUTHN,
            json_encode($request->get('assertion')),
            ['challenge' => $challenge->code] // base64-encoded WebAuthn challenge
        );

        if (!$result) {
            return response()->json([
                'error' => 'WebAuthn verification failed.',
                'two_factor_failed' => true,
            ], 401);
        }

        return response()->json($this->withTrustedDevice($request, $result));
    }

    // ========================================================================
    // Management Endpoints (authenticated via JWT)
    // ========================================================================

    /**
     * Get 2FA status for the authenticated user.
     *
     * GET /_user/api/v1/2fa/status
     */
    public function status(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);
            return response()->json($this->service->getStatus($user));
        } catch (AuthenticationException|TokenBlacklistedException $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    /**
     * Begin TOTP setup (returns QR code and secret).
     *
     * POST /_user/api/v1/2fa/totp/setup
     */
    public function totpSetup(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);

            if (!$this->service->isMethodAvailable(TwoFactorMethod::METHOD_TOTP)) {
                return response()->json(['error' => 'TOTP is not available.'], 403);
            }

            $setupData = $this->service->setupTotp($user);

            return response()->json($setupData);
        } catch (AuthenticationException|TokenBlacklistedException $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    /**
     * Confirm TOTP setup with a verification code.
     *
     * POST /_user/api/v1/2fa/totp/confirm
     * Body: { secret, code }
     */
    public function totpConfirm(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);

            $validation = Validator::make($request->all(), [
                'secret' => 'required|string',
                'code' => 'required|string|min:6|max:6',
            ]);

            if ($validation->fails()) {
                return response()->json([
                    'error' => $validation->errors()->first(),
                    'errors' => $validation->errors()->toArray(),
                ], 422);
            }

            $confirmed = $this->service->confirmTotp(
                $user,
                $request->get('secret'),
                $request->get('code')
            );

            if (!$confirmed) {
                return response()->json(['error' => 'Invalid verification code.'], 422);
            }

            // Return recovery codes if this is the first time
            $status = $this->service->getStatus($user);

            return response()->json([
                'message' => 'TOTP enabled successfully.',
                'status' => $status,
            ]);
        } catch (AuthenticationException|TokenBlacklistedException $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    /**
     * Disable TOTP.
     *
     * DELETE /_user/api/v1/2fa/totp
     */
    public function totpDisable(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);
            $this->service->disableMethod($user, TwoFactorMethod::METHOD_TOTP);

            return response()->json([
                'message' => 'TOTP disabled.',
                'status' => $this->service->getStatus($user),
            ]);
        } catch (AuthenticationException|TokenBlacklistedException $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    /**
     * Enable email 2FA.
     *
     * POST /_user/api/v1/2fa/email/enable
     */
    public function emailEnable(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);

            if (!$this->service->isMethodAvailable(TwoFactorMethod::METHOD_EMAIL)) {
                return response()->json(['error' => 'Email 2FA is not available.'], 403);
            }

            $this->service->enableEmailMethod($user);

            return response()->json([
                'message' => 'Email 2FA enabled.',
                'status' => $this->service->getStatus($user),
            ]);
        } catch (AuthenticationException|TokenBlacklistedException $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    /**
     * Disable email 2FA.
     *
     * DELETE /_user/api/v1/2fa/email
     */
    public function emailDisable(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);
            $this->service->disableMethod($user, TwoFactorMethod::METHOD_EMAIL);

            return response()->json([
                'message' => 'Email 2FA disabled.',
                'status' => $this->service->getStatus($user),
            ]);
        } catch (AuthenticationException|TokenBlacklistedException $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    /**
     * Get WebAuthn registration options.
     *
     * POST /_user/api/v1/2fa/webauthn/register/options
     */
    public function webauthnRegisterOptions(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);

            if (!$this->service->isMethodAvailable(TwoFactorMethod::METHOD_WEBAUTHN)) {
                return response()->json(['error' => 'WebAuthn is not available.'], 403);
            }

            $options = $this->service->getWebAuthnRegistrationOptions($user);

            return response()->json($options);
        } catch (AuthenticationException|TokenBlacklistedException $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    /**
     * Complete WebAuthn registration.
     *
     * POST /_user/api/v1/2fa/webauthn/register
     * Body: { attestation: { clientDataJSON, attestationObject, transports? }, name? }
     */
    public function webauthnRegister(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);

            $validation = Validator::make($request->all(), [
                'attestation' => 'required|array',
                'attestation.clientDataJSON' => 'required|string',
                'attestation.attestationObject' => 'required|string',
                'challenge' => 'required|string',
                'name' => 'nullable|string|max:255',
            ]);

            if ($validation->fails()) {
                return response()->json([
                    'error' => $validation->errors()->first(),
                    'errors' => $validation->errors()->toArray(),
                ], 422);
            }

            $credential = $this->service->registerWebAuthn(
                $user,
                $request->get('attestation'),
                $request->get('challenge'),
                $request->get('name')
            );

            return response()->json([
                'message' => 'Security key registered successfully.',
                'credential' => [
                    'id' => $credential->id,
                    'name' => $credential->name ?? 'Security Key',
                    'created_at' => $credential->created_at->toIso8601String(),
                ],
                'status' => $this->service->getStatus($user),
            ]);
        } catch (AuthenticationException|TokenBlacklistedException $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Registration failed: ' . $e->getMessage()], 422);
        }
    }

    /**
     * Remove a WebAuthn credential.
     *
     * DELETE /_user/api/v1/2fa/webauthn/{id}
     */
    public function webauthnRemove(Request $request, int $id): JsonResponse
    {
        try {
            $user = $this->authorize($request);
            $removed = $this->service->removeWebAuthnCredential($user, $id);

            if (!$removed) {
                return response()->json(['error' => 'Credential not found.'], 404);
            }

            return response()->json([
                'message' => 'Security key removed.',
                'status' => $this->service->getStatus($user),
            ]);
        } catch (AuthenticationException|TokenBlacklistedException $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    /**
     * View recovery codes (requires password confirmation).
     *
     * GET /_user/api/v1/2fa/recovery-codes
     * Query: password (required)
     */
    public function recoveryCodes(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);

            $password = $request->get('password');
            if (!$password || !$user->checkHashValue('password', $password)) {
                return response()->json(['error' => 'Password confirmation required.'], 403);
            }

            $remaining = \Golem15\User\Models\TwoFactorRecoveryCode::where('user_id', $user->id)
                ->whereNull('used_at')
                ->count();

            return response()->json([
                'recovery_codes_remaining' => $remaining,
                'message' => 'Recovery codes cannot be viewed after creation. Regenerate to get new codes.',
            ]);
        } catch (AuthenticationException|TokenBlacklistedException $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    /**
     * Regenerate recovery codes.
     *
     * POST /_user/api/v1/2fa/recovery-codes/regenerate
     * Body: { password }
     */
    public function regenerateRecoveryCodes(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);

            $password = $request->get('password');
            if (!$password || !$user->checkHashValue('password', $password)) {
                return response()->json(['error' => 'Password confirmation required.'], 403);
            }

            $codes = $this->service->generateRecoveryCodes($user);

            return response()->json([
                'recovery_codes' => $codes,
                'message' => 'Save these codes securely. They will not be shown again.',
            ]);
        } catch (AuthenticationException|TokenBlacklistedException $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    // ========================================================================
    // Trusted Device Management Endpoints
    // ========================================================================

    /**
     * Revoke a single trusted device.
     *
     * DELETE /_user/api/v1/2fa/trusted-devices/{id}
     */
    public function trustedDeviceRevoke(Request $request, int $id): JsonResponse
    {
        try {
            $user = $this->authorize($request);
            $revoked = $this->service->revokeTrustedDevice($id, $user);

            if (!$revoked) {
                return response()->json(['error' => 'Device not found.'], 404);
            }

            return response()->json([
                'message' => 'Device revoked.',
                'status' => $this->service->getStatus($user),
            ]);
        } catch (AuthenticationException|TokenBlacklistedException $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    /**
     * Revoke all trusted devices.
     *
     * DELETE /_user/api/v1/2fa/trusted-devices
     */
    public function trustedDeviceRevokeAll(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);
            $this->service->revokeAllTrustedDevices($user);

            return response()->json([
                'message' => 'All trusted devices revoked.',
                'status' => $this->service->getStatus($user),
            ]);
        } catch (AuthenticationException|TokenBlacklistedException $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    /**
     * If trust_device is requested and trusted devices are enabled,
     * create a trusted device token and add it to the result.
     */
    protected function withTrustedDevice(Request $request, array $result): array
    {
        if ($request->get('trust_device') && $this->service->isTrustedDeviceEnabled()) {
            $user = UserModel::find($result['user']['id'] ?? null);
            if ($user) {
                $result['trusted_device_token'] = $this->service->createTrustedDeviceToken($user);
            }
        }

        return $result;
    }

    /**
     * Authorize the request via JWT and return the user.
     *
     * Mirrors ApiController::authorize() -- every JWT failure mode (expired,
     * malformed, blacklisted, rotated secret) is normalised to
     * AuthenticationException so callers return 401 instead of letting the raw
     * JWTException escape into an unhandled 500 plus a logged stack trace.
     *
     * @throws AuthenticationException
     */
    protected function authorize(Request $request): UserModel
    {
        $token = TokenExtractor::fromRequest($request);
        if (!$token) {
            throw new AuthenticationException('Token not found');
        }

        try {
            $user = JWTAuth::setToken($token)->toUser();
        } catch (JWTException) {
            // Deliberately not chained: Illuminate's AuthenticationException
            // takes ($message, array $guards, $redirectTo) and has no $previous
            // slot. Nothing is lost -- the reason a token failed must not reach
            // the client anyway, or it becomes an oracle.
            throw new AuthenticationException('Unauthorized');
        }

        if (!$user) {
            throw new AuthenticationException('Unauthorized');
        }

        return $user;
    }
}
