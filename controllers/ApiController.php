<?php

namespace Golem15\User\Controllers;

use Golem15\User\Classes\AuthManager;
use Golem15\User\Classes\TokenExtractor;
use Golem15\User\Models\Settings;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

class ApiController
{
    public const ADMIN_USERS_GROUP = 'admin';

    public function login(Request $request): JsonResponse
    {
        $credentials['password'] = $request->get('password');
        $loginAttribute = Settings::get('login_attribute');
        $credentials[$loginAttribute] = $request->get($loginAttribute);

        try {
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'Unauthorized'], 401);
            }
            JWTAuth::setToken($token);
            $userModel = JWTAuth::toUser();
            event('golem15.user.login', [$userModel]);
            return response()->json(['token' => $token, 'user' => $userModel->toArray()]);
        } catch (AuthException $e) {
            return response()->json(
                [
                    'error'   => true,
                    'message' => $e->getMessage(),
                ],
                401
            );
        } catch (\Exception $e) {
            return response()->json(
                [
                    'error'   => true,
                    'message' => $e->getMessage(),
                ],
                500
            );
        }
    }

    public function logout(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize(($request));
            $authManager = AuthManager::instance();
            $authManager->logout();
            JWTAuth::invalidate();
            event('golem15.user.logout', [$user]);
            return response()->json(['message' => 'Logged out']);
        } catch (AuthenticationException $e) {
            return response()->json(
                [
                    'error'   => true,
                    'message' => $e->getMessage(),
                ],
                500
            );
        }
    }

    public function fetch(Request $request): JsonResponse
    {
        try {
            $user = $this->authorize($request);
            return response()->json(['user' => $user->toArray()]);
        } catch (AuthenticationException $e) {
            return response()->json(
                [
                    'error'   => true,
                    'message' => $e->getMessage(),
                ],
                500
            );
        }
    }

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

    public function activate(Request $request): JsonResponse
    {

    }

    public function register(Request $request): JsonResponse
    {

    }

    public function update(Request $request): JsonResponse
    {

    }
    public function forgotPassword(Request $request): JsonResponse
    {

    }

    public function resetPassword(Request $request): JsonResponse
    {

    }



    public function authorize(Request $request) {
        $token = TokenExtractor::fromRequest($request);
        if ($token) {
            return \Cache::remember('g15user_'.$token, 60, static function () use ($token) {
                JWTAuth::setToken($token);
                return JWTAuth::toUser($token);
            });
        }
        throw new AuthenticationException('Token not found');
    }
}
