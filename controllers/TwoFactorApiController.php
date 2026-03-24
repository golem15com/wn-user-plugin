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

        return response()->json($result);
    }

    /**
     * Use a recovery code to bypass 2FA.
     *
     * POST /_user/api/v1/2fa/recovery
     * Body: { challenge_token, code: "XXXXX-XXXXX" }
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

        return response()->json($result);
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

        return response()->json($result);
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

            // Store challenge in session for verification
            session(['webauthn_register_challenge' => $options['challenge']]);

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
                'name' => 'nullable|string|max:255',
            ]);

            if ($validation->fails()) {
                return response()->json([
                    'error' => $validation->errors()->first(),
                    'errors' => $validation->errors()->toArray(),
                ], 422);
            }

            $challenge = session('webauthn_register_challenge');
            if (!$challenge) {
                return response()->json(['error' => 'No registration challenge found. Request options first.'], 422);
            }

            $credential = $this->service->registerWebAuthn(
                $user,
                $request->get('attestation'),
                $challenge,
                $request->get('name')
            );

            session()->forget('webauthn_register_challenge');

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
    // Helpers
    // ========================================================================

    /**
     * Authorize the request via JWT and return the user.
     */
    protected function authorize(Request $request): UserModel
    {
        $token = TokenExtractor::fromRequest($request);
        if (!$token) {
            throw new AuthenticationException('Token not found');
        }

        JWTAuth::setToken($token);
        $user = JWTAuth::toUser();
        if (!$user) {
            throw new AuthenticationException('Unauthorized');
        }

        return $user;
    }
}
