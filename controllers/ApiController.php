<?php

namespace Golem15\User\Controllers;

use Golem15\User\Classes\AuthManager;
use Golem15\User\Classes\TokenExtractor;
use Golem15\User\Facades\Auth;
use Golem15\User\Models\DeviceAuthSession;
use Golem15\User\Models\Settings as UserSettings;
use Golem15\User\Models\User as UserModel;
use Illuminate\Auth\AuthenticationException;
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
use Winter\Storm\Exception\ApplicationException;
use Winter\Storm\Support\Facades\Event;

class ApiController
{
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
                return response()->json(['error' => 'Unauthorized'], 401);
            }
            JWTAuth::setToken($token);
            $userModel = JWTAuth::toUser();
            event('golem15.user.login', [$userModel]);
            return response()->json(['token' => $token, 'user' => $userModel->getApiArray()]);
        } catch (AuthException $e) {
            return response()->json(
                [
                    'error' => true,
                    'message' => $e->getMessage(),
                ],
                401
            );
        } catch (\Exception $e) {
            return response()->json(
                [
                    'error' => true,
                    'message' => $e->getMessage(),
                ],
                500
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
                return response()->json(['error' => 'Could not refresh token', 'msg' => $e->getMessage()], 500);
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
       //         throw new ApplicationException(Lang::get(/*Registration is throttled. Please try again later.*/'golem15.user::lang.account.registration_throttled'));
            }

            /*
             * Validate input
             */
            $data = post();

            if (!array_key_exists('password_confirmation', $data)) {
                $data['password_confirmation'] = post('password');
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
        catch (Exception $ex) {
            if (Request::ajax()) throw $ex;
            else Flash::error($ex->getMessage());
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
            'user_id' => 'required|integer|exists:users,id',
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

        if (!$user) {
            return response()->json([
                'success' => false,
                'error' => ['message' => 'User not found'],
            ], 404);
        }

        // Verify user is a child (has parent_id set)
        if (!$user->hasParent()) {
            return response()->json([
                'success' => false,
                'error' => ['message' => 'PIN login is only available for children'],
            ], 403);
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

        // If user doesn't have PIN, allow direct access
        if (!$userHasPin) {
            // Generate JWT for the child
            $token = JWTAuth::fromUser($user);
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
                'error' => ['message' => 'Invalid PIN'],
            ], 401);
        }

        // Generate JWT token
        try {
            $token = JWTAuth::fromUser($user);
            JWTAuth::setToken($token);

            event('golem15.user.login', [$user]);

            \Log::info('PIN login successful', [
                'user_id' => $user->id,
                'user_name' => $user->name,
            ]);

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

        // Check if target user has a PIN set
        if (empty($targetUser->pin)) {
            return response()->json([
                'success' => false,
                'error' => ['message' => 'No PIN set for this account'],
            ], 400);
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

        // Return success with target user data
        return response()->json([
            'success' => true,
            'message' => 'PIN verified',
            'user' => $targetUser->getApiArray(),
        ]);
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
        $providers = ['google', 'facebook', 'github'];
        $enabled = [];

        foreach ($providers as $provider) {
            $clientId = config("services.{$provider}.client_id");
            $clientSecret = config("services.{$provider}.client_secret");

            if (!empty($clientId) && !empty($clientSecret)) {
                $enabled[] = $provider;
            }
        }

        return response()->json([
            'success' => true,
            'providers' => $enabled,
        ]);
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
