<?php

namespace Golem15\User\Controllers;

use Golem15\User\Classes\AuthManager;
use Golem15\User\Classes\TokenExtractor;
use Golem15\User\Facades\Auth;
use Golem15\User\Models\DeviceAuthSession;
use Golem15\User\Models\Settings as UserSettings;
use Golem15\User\Models\User as UserModel;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Request as RequestFacade;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use PHPOpenSourceSaver\JWTAuth\Contracts\JWTSubject;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenBlacklistedException;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use Winter\Storm\Auth\AuthenticationException as AuthException;
use Golem15\User\Classes\TwoFactor\TwoFactorService;
use Winter\Storm\Exception\ApplicationException;
use Winter\Storm\Support\Facades\Event;
use Golem15\Apparatus\Classes\Traits\SafeExceptionResponse;

class ApiController
{
    use SafeExceptionResponse;

    public const ADMIN_USERS_GROUP = 'admin';

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function login(Request $request): JsonResponse
    {
        $credentials['password'] = $request->get('password');
        $loginAttribute = $this->loginAttribute();
        $credentials[$loginAttribute] = $request->get($loginAttribute);

        try {
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => Lang::get('golem15.user::lang.account.invalid_login')], 401);
            }
            JWTAuth::setToken($token);
            $userModel = JWTAuth::toUser();

            // 2FA check: if enabled, check for trusted device token or return challenge
            $twoFactorService = app(TwoFactorService::class);
            if ($twoFactorService->isEnabledForUser($userModel)) {
                // Check if a valid trusted device token was provided
                $trustedDeviceToken = $request->get('trusted_device_token');
                if ($trustedDeviceToken && $twoFactorService->isTrustedDeviceEnabled()
                    && $twoFactorService->checkTrustedDeviceToken($userModel->id, $trustedDeviceToken)) {
                    // Trusted device is valid, skip 2FA
                    event('golem15.user.login', [$userModel]);
                    return response()->json(['token' => $token, 'user' => $userModel->getApiArray()]);
                }

                JWTAuth::invalidate($token);
                $challenge = $twoFactorService->createChallenge(
                    $userModel, $request->ip(), $request->userAgent()
                );
                return response()->json([
                    'two_factor_required' => true,
                    'challenge_token' => $challenge->token,
                    'available_methods' => $twoFactorService->getEnabledMethods($userModel),
                    'expires_at' => $challenge->expires_at->toIso8601String(),
                ]);
            }

            event('golem15.user.login', [$userModel]);
            return response()->json(['token' => $token, 'user' => $userModel->getApiArray()]);
        } catch (AuthException $e) {
            return response()->json(
                [
                    'error' => true,
                    'message' => Lang::get('golem15.user::lang.account.invalid_login'),
                ],
                401
            );
        } catch (\Exception $e) {
            return response()->json(
                [
                    'error' => true,
                    'message' => $this->safeExceptionMessage($e),
                ],
                $this->safeExceptionStatus($e)
            );
        }
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function logout(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize(($request));
            $authManager = AuthManager::instance();
            $authManager->logout(true);
            event('golem15.user.logout', [$user]);

            return response()->json(['message' => 'Logged out']);
        } catch (AuthenticationException|TokenBlacklistedException $e) {
            return response()->json(
                [
                    'error' => true,
                    'message' => 'Unauthorized',
                ],
                500
            );
        }
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function fetch(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);
            return response()->json(['user' => $user->getApiArray()]);
        } catch (AuthenticationException|TokenBlacklistedException $e)
        {
            return response()->json(
                [
                    'error' => true,
                    'message' => 'Unauthorized',
                ],
                401
            );
        }
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function refresh(Request $request): JsonResponse
    {
        $token = TokenExtractor::fromRequest($request);
        if ($token) {
            try {
                JWTAuth::setToken($token);
                if (!$token = JWTAuth::refresh($token)) {
                    return response()->json(['error' => 'Could not refresh token'], 401);
                }
                return response()->json(['token' => $token]);
            } catch (\Exception $e) {
                $msg = $this->safeExceptionMessage($e);
                return response()->json(['error' => 'Could not refresh token', 'msg' => $msg], $this->safeExceptionStatus($e));
            }
        }
        return response()->json(['error' => 'Token not found'], 401);
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function activate(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);
            $user->attemptActivation($request->get('code'));
            return response()->json(['user' => $user->getApiArray()]);
        } catch (AuthenticationException|TokenBlacklistedException $e)
        {
            return response()->json(
                [
                    'error' => true,
                    'message' => 'Unauthorized',
                ],
                401
            );
        }
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function register(Request $request): JsonResponse
    {
        try {
            if (!$this->canRegister()) {
                throw new ApplicationException(Lang::get(/*Registrations are currently disabled.*/'golem15.user::lang.account.registration_disabled'));
            }

            if ($this->isRegisterThrottled()) {
                throw new ApplicationException(Lang::get(/*Registration is throttled. Please try again later.*/'golem15.user::lang.account.registration_throttled'));
            }

            /*
             * Validate input
             * Use $request->all() to support both JSON and form-urlencoded data
             */
            $data = $request->all();

            if (!array_key_exists('password_confirmation', $data)) {
                $data['password_confirmation'] = $data['password'] ?? null;
            }

            $rules = (new UserModel)->rules;

            if ($this->loginAttribute() !== UserSettings::LOGIN_USERNAME) {
                unset($rules['username']);
            }

            $validation = Validator::make($data, $rules);
            if ($validation->fails()) {
                throw new ValidationException($validation);
            }

            /*
             * Record IP address
             */
            if ($ipAddress = RequestFacade::ip()) {
                $data['created_ip_address'] = $data['last_ip_address'] = $ipAddress;
            }

            /*
             * Register user
             */
            Event::fire('golem15.user.beforeRegister', [&$data]);

            $requireActivation = UserSettings::get('require_activation', true);
            $automaticActivation = UserSettings::get('activate_mode') == UserSettings::ACTIVATE_AUTO;
            $userActivation = UserSettings::get('activate_mode') == UserSettings::ACTIVATE_USER;
            $adminActivation = UserSettings::get('activate_mode') == UserSettings::ACTIVATE_ADMIN;
            $user = Auth::register($data, $automaticActivation);

            Event::fire('golem15.user.register', [$user, $data]);

            /*
             * Activation is by the user, send the email
             */
            if ($userActivation) {
                $this->sendActivationEmail($user);
                return response()->json(['message' => 'Activation email sent']);
            }

            /*
             * Automatically activated or not required, log the user in
             */
            if ($automaticActivation || !$requireActivation) {
                // Use only login credentials for JWTAuth::attempt (same pattern as login method)
                // Passing all $data causes SQL error with non-column fields like password_confirmation, GDPR fields
                $credentials = [
                    $this->loginAttribute() => $data['email'],
                    'password' => $data['password']
                ];
                $token = JWTAuth::attempt($credentials);
                JWTAuth::setToken($token);
                $userModel = JWTAuth::toUser();
                event('golem15.user.login', [$userModel]);
                return response()->json(['token' => $token, 'user' => $userModel->getApiArray()]);
            }


        }
        catch (ValidationException $ex) {
            return response()->json([
                'error' => $ex->validator->errors()->first(),
                'errors' => $ex->validator->errors()->toArray(),
            ], 422);
        }
        catch (Exception $ex) {
            return response()->json([
                'error' => $this->safeExceptionMessage($ex),
            ], $this->safeExceptionStatus($ex));
        }
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function update(Request $request): JsonResponse
    {

    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function forgotPassword(Request $request): JsonResponse
    {

    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function resetPassword(Request $request): JsonResponse
    {

    }

    /**
     * PIN login for children
     *
     * Allows children to authenticate using their PIN code instead of password.
     * Returns a JWT token on success.
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function pinLogin(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'user_id' => 'required|integer',
            'pin' => 'nullable|string|size:4',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'error' => [
                    'message' => 'Validation failed',
                    'code' => 'VALIDATION_ERROR',
                    'details' => $validator->errors(),
                ],
            ], 422);
        }

        $user = UserModel::find($request->get('user_id'));

        // Generic error for user-not-found or not-a-child (prevents enumeration)
        if (!$user || !$user->hasParent()) {
            return response()->json([
                'success' => false,
                'error' => ['message' => 'Invalid credentials'],
            ], 401);
        }

        // Check if user has a PIN set
        $userHasPin = !empty($user->pin);
        $providedPin = $request->get('pin');

        // If user has PIN, require it
        if ($userHasPin && !$providedPin) {
            return response()->json([
                'success' => false,
                'error' => ['message' => 'PIN is required for this account'],
            ], 400);
        }

        // PIN-less children: require authenticated parent in same family
        if (!$userHasPin) {
            $parent = $this->getAuthenticatedParent();
            if (!$parent || $parent->family_id !== $user->family_id) {
                return response()->json([
                    'success' => false,
                    'error' => ['message' => 'Invalid credentials'],
                ], 401);
            }

            // Generate JWT for the child
            $token = JWTAuth::fromUser($user);
            event('golem15.user.login', [$user]);
            return response()->json([
                'token' => $token,
                'user' => $user->getApiArray()
            ]);
        }

        // Check if PIN is locked
        if ($user->isPinLocked()) {
            $minutesLeft = abs($user->getPinLockoutMinutes());
            return response()->json([
                'success' => false,
                'error' => [
                    'message' => "Too many failed attempts. Please try again in {$minutesLeft} minutes.",
                    'code' => 'PIN_LOCKED',
                    'details' => ['minutes_remaining' => $minutesLeft],
                ],
            ], 429);
        }

        // Verify PIN
        if (!$user->verifyPin($request->get('pin'))) {
            // Check again if now locked after failed attempt
            if ($user->isPinLocked()) {
                $minutesLeft = abs($user->getPinLockoutMinutes());
                return response()->json([
                    'success' => false,
                    'error' => [
                        'message' => "Too many failed attempts. Please try again in {$minutesLeft} minutes.",
                        'code' => 'PIN_LOCKED',
                        'details' => ['minutes_remaining' => $minutesLeft],
                    ],
                ], 429);
            }

            return response()->json([
                'success' => false,
                'error' => ['message' => 'Invalid credentials'],
            ], 401);
        }

        // Generate JWT token
        try {
            $token = JWTAuth::fromUser($user);
            JWTAuth::setToken($token);

            event('golem15.user.login', [$user]);

            return response()->json([
                'success' => true,
                'data' => [
                    'token' => $token,
                    'user' => $user->getApiArray(),
                ],
            ]);
        } catch (\Exception $e) {
            \Log::error('PIN login JWT generation failed', [
                'user_id' => $user->id,
                'error' => $e->getMessage(),
            ]);

            return response()->json([
                'success' => false,
                'error' => ['message' => 'Failed to generate authentication token'],
            ], 500);
        }
    }

    /**
     * Verify PIN for authenticated user
     *
     * Allows parents to verify their own PIN on the user picker.
     * Does not issue a new token - just confirms the PIN is correct.
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function verifyPin(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);
        } catch (AuthenticationException|TokenBlacklistedException $e) {
            return response()->json([
                'success' => false,
                'error' => ['message' => 'Unauthorized'],
            ], 401);
        }

        $validator = Validator::make($request->all(), [
            'pin' => 'required|string|size:4',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'error' => [
                    'message' => 'Validation failed',
                    'details' => $validator->errors(),
                ],
            ], 422);
        }

        // Check if user has a PIN set
        if (empty($user->pin)) {
            return response()->json([
                'success' => false,
                'error' => ['message' => 'No PIN set for this account'],
            ], 400);
        }

        // Check if PIN is locked
        if ($user->isPinLocked()) {
            $minutesLeft = abs($user->getPinLockoutMinutes());
            return response()->json([
                'success' => false,
                'error' => [
                    'message' => "Too many failed attempts. Please try again in {$minutesLeft} minutes.",
                    'code' => 'PIN_LOCKED',
                    'details' => ['minutes_remaining' => $minutesLeft],
                ],
            ], 429);
        }

        // Verify PIN
        if (!$user->verifyPin($request->get('pin'))) {
            // Check again if now locked after failed attempt
            if ($user->isPinLocked()) {
                $minutesLeft = abs($user->getPinLockoutMinutes());
                return response()->json([
                    'success' => false,
                    'error' => [
                        'message' => "Too many failed attempts. Please try again in {$minutesLeft} minutes.",
                        'code' => 'PIN_LOCKED',
                        'details' => ['minutes_remaining' => $minutesLeft],
                    ],
                ], 429);
            }

            return response()->json([
                'success' => false,
                'error' => ['message' => 'Invalid PIN'],
            ], 401);
        }

        return response()->json([
            'success' => true,
            'message' => 'PIN verified',
        ]);
    }

    /**
     * Verify PIN for any family member
     *
     * Used by user picker to verify parent/child PINs before switching profiles.
     * Caller must be authenticated and in the same family.
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function verifyFamilyMemberPin(Request $request): JsonResponse
    {
        try {
            $currentUser = $this->authorize($request);
        } catch (AuthenticationException|TokenBlacklistedException $e) {
            return response()->json([
                'success' => false,
                'error' => ['message' => 'Unauthorized'],
            ], 401);
        }

        $validator = Validator::make($request->all(), [
            'user_id' => 'required|integer|exists:users,id',
            'pin' => 'nullable|string|size:4',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'error' => [
                    'message' => 'Validation failed',
                    'details' => $validator->errors(),
                ],
            ], 422);
        }

        $targetUser = UserModel::find($request->get('user_id'));

        if (!$targetUser) {
            return response()->json([
                'success' => false,
                'error' => ['message' => 'User not found'],
            ], 404);
        }

        // Verify same family
        if ($targetUser->family_id !== $currentUser->family_id) {
            return response()->json([
                'success' => false,
                'error' => ['message' => 'User is not in your family'],
            ], 403);
        }

        // If target user has no PIN, allow switching (return token for parents)
        if (empty($targetUser->pin)) {
            $responseData = [
                'success' => true,
                'message' => 'No PIN required',
                'user' => $targetUser->getApiArray(),
            ];
            if ($targetUser->isParent()) {
                $responseData['token'] = JWTAuth::fromUser($targetUser);
            }
            return response()->json($responseData);
        }

        // Check if PIN is locked
        if ($targetUser->isPinLocked()) {
            $minutesLeft = abs($targetUser->getPinLockoutMinutes());
            return response()->json([
                'success' => false,
                'error' => [
                    'message' => "Too many failed attempts. Please try again in {$minutesLeft} minutes.",
                    'code' => 'PIN_LOCKED',
                    'details' => ['minutes_remaining' => $minutesLeft],
                ],
            ], 429);
        }

        // Verify PIN
        if (!$targetUser->verifyPin($request->get('pin'))) {
            // Check again if now locked after failed attempt
            if ($targetUser->isPinLocked()) {
                $minutesLeft = abs($targetUser->getPinLockoutMinutes());
                return response()->json([
                    'success' => false,
                    'error' => [
                        'message' => "Too many failed attempts. Please try again in {$minutesLeft} minutes.",
                        'code' => 'PIN_LOCKED',
                        'details' => ['minutes_remaining' => $minutesLeft],
                    ],
                ], 429);
            }

            return response()->json([
                'success' => false,
                'error' => ['message' => 'Invalid PIN'],
            ], 401);
        }

        // Return success with target user data (include JWT for parents)
        $responseData = [
            'success' => true,
            'message' => 'PIN verified',
            'user' => $targetUser->getApiArray(),
        ];
        if ($targetUser->isParent()) {
            $responseData['token'] = JWTAuth::fromUser($targetUser);
        }
        return response()->json($responseData);
    }

    /**
     * Get enabled OAuth providers
     *
     * Returns a list of OAuth providers that are configured and available for login.
     * A provider is considered enabled if both client_id and client_secret are set.
     *
     * @return JsonResponse
     */
    public function oauthProviders(): JsonResponse
    {
        $providers = ['google', 'facebook'];
        $labels = [
            'google' => 'Kontynuuj z Google',
            'facebook' => 'Kontynuuj z Facebookiem',
        ];
        $enabled = [];

        foreach ($providers as $provider) {
            $clientId = config("services.{$provider}.client_id");
            $clientSecret = config("services.{$provider}.client_secret");

            if (!empty($clientId) && !empty($clientSecret)) {
                $enabled[] = [
                    'name' => $provider,
                    'label' => $labels[$provider] ?? ucfirst($provider),
                ];
            }
        }

        return response()->json([
            'success' => true,
            'providers' => $enabled,
        ]);
    }

    /**
     * Redeem a one-time OAuth completion code generated during provider callback.
     */
    public function oauthComplete(Request $request): JsonResponse
    {
        $code = (string) $request->query('code', '');

        if ($code === '') {
            return response()->json(['error' => 'Missing OAuth completion code'], 422);
        }

        $payload = Cache::pull('oauth-complete:' . $code);
        if (!is_array($payload)) {
            return response()->json(['error' => 'OAuth completion code is invalid or expired'], 410);
        }

        return response()->json([
            'token' => $payload['token'] ?? null,
            'user' => $payload['user'] ?? null,
            'action' => $payload['action'] ?? 'login',
            'return_to' => $payload['return_to'] ?? '/',
        ]);
    }

    public function oauthRegisterComplete(Request $request): JsonResponse
    {
        $pendingCode = (string) $request->input('pending_code', '');
        if ($pendingCode === '') {
            return response()->json(['error' => 'Missing pending registration code'], 422);
        }

        $payload = Cache::get('oauth-pending-registration:' . $pendingCode);
        if (!is_array($payload)) {
            return response()->json(['error' => 'OAuth registration session is invalid or expired'], 410);
        }

        $termsAccepted = (bool) $request->input('terms_accepted', false);
        $privacyAccepted = (bool) $request->input('privacy_accepted', false);
        $marketingConsent = (bool) $request->input('marketing_consent', false);

        if (!$termsAccepted || !$privacyAccepted) {
            return response()->json([
                'error' => 'Musisz zaakceptować regulamin i politykę prywatności, aby dokończyć rejestrację.',
                'errors' => [
                    'terms_accepted' => !$termsAccepted ? ['Musisz zaakceptować regulamin.'] : [],
                    'privacy_accepted' => !$privacyAccepted ? ['Musisz zaakceptować politykę prywatności.'] : [],
                ],
            ], 422);
        }

        $payload['terms_accepted'] = true;
        $payload['privacy_accepted'] = true;
        $payload['marketing_consent'] = $marketingConsent;

        try {
            $component = new \Golem15\User\Components\SocialAuth();
            $result = $component->completePendingRegistration($payload);
            Cache::forget('oauth-pending-registration:' . $pendingCode);

            return response()->json([
                'token' => $result['token'],
                'user' => $result['user'],
                'action' => $result['action'] ?? 'register',
                'return_to' => $result['return_to'] ?? '/',
            ]);
        } catch (ValidationException $ex) {
            return response()->json([
                'error' => $ex->validator->errors()->first(),
                'errors' => $ex->validator->errors()->toArray(),
            ], 422);
        } catch (ApplicationException $ex) {
            return response()->json(['error' => $ex->getMessage()], 422);
        } catch (\Exception $ex) {
            return response()->json(['error' => $this->safeExceptionMessage($ex)], $this->safeExceptionStatus($ex));
        }
    }

    /**
     * GET /devices
     * List authorized devices for current user
     */
    public function listDevices(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $devices = DeviceAuthSession::where('user_id', $user->id)
            ->whereIn('status', [DeviceAuthSession::STATUS_CONFIRMED, DeviceAuthSession::STATUS_USED])
            ->orderBy('last_activity_at', 'desc')
            ->get();

        $currentSessionId = session()->getId();

        $result = $devices->map(function ($device) use ($currentSessionId) {
            return [
                'id' => $device->id,
                'device_name' => $device->device_name_attribute,
                'device_ip' => $device->device_ip,
                'authorized_at' => $device->confirmed_at?->toIso8601String(),
                'last_activity' => $device->last_activity_at?->toIso8601String(),
                'is_current' => $device->session_id === $currentSessionId,
            ];
        });

        return response()->json(['success' => true, 'devices' => $result]);
    }

    /**
     * DELETE /devices/{id}
     * Revoke a device authorization
     */
    public function revokeDevice(Request $request, int $id): JsonResponse
    {
        try {
            $user = $this->authorize($request);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $device = DeviceAuthSession::where('id', $id)
            ->where('user_id', $user->id)
            ->first();

        if (!$device) {
            return response()->json(['error' => 'Device not found'], 404);
        }

        $device->revoke();

        return response()->json(['success' => true, 'message' => 'Device revoked successfully']);
    }

    /**
     * POST /devices/authorize
     * Authorize a device using short code (XXXX-XXXX format) or token (from QR code)
     */
    public function authorizeDevice(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $session = null;

        // Try short code first
        if ($request->has('short_code')) {
            $code = str_replace('-', '', $request->input('short_code', ''));

            if (strlen($code) !== 8) {
                return response()->json(['error' => 'Please enter a valid 8-character code'], 422);
            }

            $session = DeviceAuthSession::findValidShortCode($code);
        }
        // Try token (from QR code scan)
        elseif ($request->has('token')) {
            $session = DeviceAuthSession::findValidToken($request->input('token'));
        }

        if (!$session) {
            return response()->json(['error' => 'Invalid or expired code'], 400);
        }

        // Link to user if not already linked
        if (!$session->user_id) {
            $session->user_id = $user->id;
        }

        $session->confirm($request->ip());

        return response()->json(['success' => true, 'message' => 'Device authorized successfully']);
    }

    /**
     * POST /devices/initiate
     * Initiate a new device authorization session (called by new/unauthorized device)
     * Returns QR code data and short code for display
     */
    public function initiateDeviceAuth(Request $request): JsonResponse
    {
        // This endpoint can be called without auth (new device doesn't have token yet)
        // But we need to associate it with a user later when parent confirms

        $deviceInfo = [
            'ip' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'name' => $request->input('device_name'),
        ];

        // Create session without user_id - will be linked when parent confirms
        $session = DeviceAuthSession::create([
            'token' => \Illuminate\Support\Str::random(64),
            'short_code' => $this->generateUniqueShortCode(),
            'user_id' => null,
            'status' => DeviceAuthSession::STATUS_PENDING,
            'expires_at' => \Carbon\Carbon::now()->addMinutes(5),
            'device_ip' => $deviceInfo['ip'],
            'device_user_agent' => $deviceInfo['user_agent'],
            'device_name' => $deviceInfo['name'],
        ]);

        return response()->json([
            'success' => true,
            'data' => [
                'token' => $session->token,
                'short_code' => $session->short_code,
                'auth_url' => $session->getAuthUrl(),
                'expires_at' => $session->expires_at->toIso8601String(),
            ],
        ]);
    }

    /**
     * GET /devices/status/{token}
     * Check authorization status (polled by new device waiting for confirmation)
     */
    public function deviceAuthStatus(Request $request, string $token): JsonResponse
    {
        $session = DeviceAuthSession::where('token', $token)->first();

        if (!$session) {
            return response()->json(['error' => 'Session not found'], 404);
        }

        // Check if expired
        if ($session->isExpired()) {
            $session->markAsExpired();
            return response()->json([
                'success' => true,
                'status' => 'expired',
                'message' => 'Authorization session has expired',
            ]);
        }

        $data = [
            'status' => $session->status,
        ];

        // If confirmed, include user info so device can complete login
        if ($session->status === DeviceAuthSession::STATUS_CONFIRMED && $session->user_id) {
            $data['user_id'] = $session->user_id;
            $data['message'] = 'Device authorized - complete login';
        }

        return response()->json([
            'success' => true,
            'data' => $data,
        ]);
    }

    /**
     * Generate a unique 8-character short code
     */
    private function generateUniqueShortCode(): string
    {
        $characters = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';

        do {
            $code = '';
            for ($i = 0; $i < 8; $i++) {
                $code .= $characters[random_int(0, strlen($characters) - 1)];
            }
            $shortCode = substr($code, 0, 4) . '-' . substr($code, 4, 4);
        } while (DeviceAuthSession::where('short_code', $shortCode)->exists());

        return $shortCode;
    }

    /**
     * Extract authenticated parent from JWT header (if present).
     * Returns null if no valid token, token is invalid, or user is not a parent.
     */
    private function getAuthenticatedParent(): ?UserModel
    {
        try {
            $token = TokenExtractor::fromRequest(request());
            if (!$token) {
                return null;
            }
            $user = JWTAuth::setToken($token)->toUser();
            return ($user && !$user->hasParent()) ? $user : null;
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * @param Request $request
     * @return mixed
     * @throws AuthenticationException
     * @throws TokenBlacklistedException
     */
    public function authorize(Request $request): UserModel
    {
        $token = TokenExtractor::fromRequest($request);
        if ($token) {
            JWTAuth::setToken($token);
            return JWTAuth::toUser($token);
        }
        throw new AuthenticationException('Token not found');
    }

    private function canRegister(): bool
    {
        return UserSettings::get('allow_registration', true);
    }

    private function isRegisterThrottled(): bool
    {
        if (!UserSettings::get('use_register_throttle', false)) {
            return false;
        }

        return UserModel::isRegisterThrottled(RequestFacade::ip());
    }

    private function loginAttribute(): string
    {
       return UserSettings::get('login_attribute');
    }

    protected function sendActivationEmail($user)
    {
        $code = implode('!', [$user->id, $user->getActivationCode()]);

        $link = $this->makeActivationUrl($code);

        $data = [
            'name' => $user->name,
            'link' => $link,
            'code' => $code
        ];

        Mail::send('golem15.user::mail.activate', $data, function($message) use ($user) {
            $message->to($user->email, $user->name);
        });
    }

    private function makeActivationUrl(string $code)
    {
        $url = env('APP_URL') . '/_user/api/v1/activate';
        if (strpos($url, $code) === false) {
            $url .= '?activate=' . $code;
        }

        return $url;
    }
}
