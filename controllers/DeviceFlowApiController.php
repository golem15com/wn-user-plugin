<?php

namespace Golem15\User\Controllers;

use Carbon\Carbon;
use Golem15\User\Classes\TokenExtractor;
use Golem15\User\Models\DeviceAuthSession;
use Golem15\User\Models\User as UserModel;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use Winter\Storm\Support\Facades\Event;

/**
 * Device-flow endpoints for API clients that hold a PKCE verifier (RFC 7636 S256).
 *
 * Only sessions created with a code_challenge ("redeemable" sessions) are served
 * here; every other session answers the generic not-found response, so the
 * legacy device flow is untouched.
 *
 * - poll / redeem: unauthenticated, the code_verifier is the credential. Never 401
 *   (an SPA interceptor would treat that as its own session expiring).
 * - describe / deny: called by a signed-in browser (JWT) holding the link token.
 *
 * Tokens, verifiers and JWTs only travel in POST bodies and are never logged.
 */
class DeviceFlowApiController
{
    /**
     * POST /devices/poll  {token, code_verifier}
     */
    public function poll(Request $request): JsonResponse
    {
        if ($invalid = $this->validateGrantRequest($request)) {
            return $invalid;
        }

        $session = $this->findVerifiedSession($request);
        if (!$session) {
            return response()->json(['error' => 'Session not found'], 404);
        }

        $this->expireIfStale($session);

        $status = $session->publicStatus();
        $data = [
            'status' => $status,
            'interval' => DeviceAuthSession::POLL_INTERVAL_SECONDS,
        ];

        if ($status === DeviceAuthSession::STATUS_CONFIRMED) {
            $data['redeem_expires_in'] = $session->secondsLeft();
        }

        return response()->json(['success' => true, 'data' => $data]);
    }

    /**
     * POST /devices/redeem  {token, code_verifier}
     *
     * Exchanges a confirmed, verifier-bound session for a JWT exactly once.
     */
    public function redeem(Request $request): JsonResponse
    {
        if ($invalid = $this->validateGrantRequest($request)) {
            return $invalid;
        }

        $session = $this->findVerifiedSession($request);
        if (!$session) {
            return response()->json(['error' => 'Invalid grant'], 404);
        }

        // One conditional UPDATE wins the grant: confirmed -> used. A concurrent
        // second redeem matches zero rows (D-10).
        $now = Carbon::now();
        $won = DeviceAuthSession::where('id', $session->id)
            ->where('status', DeviceAuthSession::STATUS_CONFIRMED)
            ->whereNotNull('user_id')
            ->where('expires_at', '>', $now)
            ->update([
                'status' => DeviceAuthSession::STATUS_USED,
                'used_at' => $now,
                'last_activity_at' => $now,
            ]);

        if ($won !== 1) {
            $session->refresh();

            if ($session->status === DeviceAuthSession::STATUS_PENDING && !$session->isExpired()) {
                return response()->json([
                    'error' => 'Authorization pending',
                    'code' => 'authorization_pending',
                ], 409);
            }

            return $this->grantGone($this->grantFailureCode($session));
        }

        $session->refresh();
        $user = $session->user;

        // Same refusals as the passwordless sign-in, answered as a dead grant.
        if (!$user
            || !$user->is_activated
            || $user->isBanned()
            || (method_exists($user, 'isChild') && $user->isChild())) {
            return $this->grantGone('access_denied');
        }

        $ip = $request->ip();
        if ($ip) {
            $user->touchIpAddress($ip);
        }

        event('golem15.user.login', [$user]);
        Event::fire('golem15.user.device.redeemed', [$user, $session, $ip]);

        return response()->json([
            'token' => JWTAuth::fromUser($user),
            'user' => $user->getApiArray(),
        ]);
    }

    /**
     * POST /devices/describe  {token}  (JWT)
     *
     * What is asking, for the browser confirm page. Details only while pending;
     * no user data, token or challenge ever.
     */
    public function describe(Request $request): JsonResponse
    {
        try {
            $this->authorize($request);
        } catch (AuthenticationException) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        if ($invalid = $this->validateTokenRequest($request)) {
            return $invalid;
        }

        $session = $this->findRedeemableSession($request);
        if (!$session) {
            return response()->json(['error' => 'Session not found'], 404);
        }

        $status = $session->publicStatus();
        if ($status !== DeviceAuthSession::STATUS_PENDING) {
            return response()->json(['success' => true, 'data' => ['status' => $status]]);
        }

        // Raw column: the model accessor invents a name ("Linux PC") when null.
        $deviceName = trim((string) ($session->getAttributes()['device_name'] ?? ''));
        $deviceName = $deviceName === '' ? null : mb_substr($deviceName, 0, 64);
        $ua = DeviceAuthSession::userAgentParts($session->device_user_agent);

        return response()->json([
            'success' => true,
            'data' => [
                'status' => $status,
                'short_code' => $session->short_code,
                'device_name' => $deviceName,
                'app' => $ua['app'],
                'os' => $ua['os'],
                'ip' => $session->device_ip,
                'created_at' => $session->created_at?->toIso8601String(),
                'expires_in' => $session->secondsLeft(),
            ],
        ]);
    }

    /**
     * POST /devices/deny  {token}  (JWT)
     *
     * Refuse a pending verifier session (revoked + denied_at).
     */
    public function deny(Request $request): JsonResponse
    {
        try {
            $this->authorize($request);
        } catch (AuthenticationException) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        if ($invalid = $this->validateTokenRequest($request)) {
            return $invalid;
        }

        $session = $this->findRedeemableSession($request);
        if (!$session) {
            return response()->json(['error' => 'Session not found'], 404);
        }

        if (!$session->deny()) {
            return response()->json([
                'error' => 'Session is not pending',
                'status' => $session->publicStatus(),
            ], 409);
        }

        return response()->json(['success' => true, 'data' => ['status' => 'denied']]);
    }

    // ------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------

    /**
     * The redeemable session for the token in the body, or null (unknown token
     * or a legacy session without a code_challenge).
     */
    protected function findRedeemableSession(Request $request): ?DeviceAuthSession
    {
        $session = DeviceAuthSession::where('token', (string) $request->input('token'))->first();

        return ($session && $session->isRedeemable()) ? $session : null;
    }

    /**
     * 422 when token / code_verifier are missing or malformed, null otherwise.
     */
    protected function validateGrantRequest(Request $request): ?JsonResponse
    {
        $validation = Validator::make($request->only(['token', 'code_verifier']), [
            'token' => ['required', 'string', 'size:64', 'alpha_num'],
            'code_verifier' => ['required', 'string', 'min:43', 'max:128', 'regex:/^[A-Za-z0-9\-._~]+$/'],
        ]);

        if ($validation->fails()) {
            return response()->json([
                'error' => 'Validation failed',
                'errors' => $validation->errors()->toArray(),
            ], 422);
        }

        return null;
    }

    /**
     * 422 when token is missing or malformed, null otherwise.
     */
    protected function validateTokenRequest(Request $request): ?JsonResponse
    {
        $validation = Validator::make($request->only(['token']), [
            'token' => ['required', 'string', 'size:64', 'alpha_num'],
        ]);

        if ($validation->fails()) {
            return response()->json([
                'error' => 'Validation failed',
                'errors' => $validation->errors()->toArray(),
            ], 422);
        }

        return null;
    }

    /**
     * The redeemable session for the token whose challenge matches the verifier,
     * or null (unknown token, legacy session, or verifier mismatch alike).
     */
    protected function findVerifiedSession(Request $request): ?DeviceAuthSession
    {
        $session = DeviceAuthSession::where('token', (string) $request->input('token'))->first();

        if (!$session || !$session->verifyCodeVerifier((string) $request->input('code_verifier'))) {
            return null;
        }

        return $session;
    }

    /**
     * Persist "expired" for a pending/confirmed session past its window. Terminal
     * rows (used, revoked, expired) are never rewritten.
     */
    protected function expireIfStale(DeviceAuthSession $session): void
    {
        if (in_array($session->status, [DeviceAuthSession::STATUS_PENDING, DeviceAuthSession::STATUS_CONFIRMED], true)
            && $session->isExpired()) {
            $session->markAsExpired();
        }
    }

    /**
     * RFC 8628-style error code for a grant that can no longer be redeemed.
     */
    protected function grantFailureCode(DeviceAuthSession $session): string
    {
        if ($session->status === DeviceAuthSession::STATUS_REVOKED) {
            return 'access_denied';
        }

        if ($session->status === DeviceAuthSession::STATUS_USED) {
            return 'grant_used';
        }

        $this->expireIfStale($session);

        return 'expired_token';
    }

    protected function grantGone(string $code): JsonResponse
    {
        return response()->json(['error' => 'Grant no longer valid', 'code' => $code], 410);
    }

    /**
     * Authorize the request via JWT and return the user.
     *
     * Mirrors TwoFactorApiController::authorize() -- every JWT failure mode is
     * normalised to AuthenticationException so callers return 401.
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
            throw new AuthenticationException('Unauthorized');
        }

        if (!$user) {
            throw new AuthenticationException('Unauthorized');
        }

        return $user;
    }
}
