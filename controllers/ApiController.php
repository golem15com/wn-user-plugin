<?php

namespace Golem15\User\Controllers;

use Golem15\User\Classes\AuthManager;
use Golem15\User\Classes\TokenExtractor;
use Golem15\User\Facades\Auth;
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
                $token = JWTAuth::attempt($data);
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
            'pin' => 'required|string|size:4',
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
        if (!$user->pin) {
            return response()->json([
                'success' => false,
                'error' => ['message' => 'No PIN has been set for this account'],
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
     * @param Request $request
     * @return mixed
     * @throws AuthenticationException
     * @throws TokenBlacklistedException
     */
    public function authorize(Request $request): User
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
