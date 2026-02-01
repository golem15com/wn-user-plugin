<?php


use Illuminate\Http\Request;

Route::group(
    ['prefix' => '/_user/api/v1', 'middleware' => ['api']],
    static function () {
        Route::options(
            '{level1?}/{level2?}/{level3?}',
            static function () {
                return Response::make('', 204);
            }
        );
        Route::post(
            'login',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->login($request);
            }
        );
        Route::post(
            'logout',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->logout($request);
            }
        );
        Route::get(
            'fetch',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->fetch($request);
            }
        );
        Route::post(
            'refresh',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->refresh($request);
            }
        );
        Route::post(
            'register',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->register($request);
            }
        );
        Route::post(
            '/forgot-password',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->forgotPassword($request);
            }
        );

        Route::post(
            '/reset-password',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->resetPassword($request);
            }
        );
        Route::post(
            '/activate',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->activate($request);
            }
        );
        Route::post(
            '/update',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->update($request);
            }
        );

        /*
         * PIN Login - for children to authenticate with their 4-digit PIN
         * This is a public endpoint (no auth required) since it initiates authentication
         */
        Route::post(
            'pin-login',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->pinLogin($request);
            }
        );

        /*
         * Verify PIN - for authenticated users to verify their own PIN
         * Used by parents on user picker to confirm their identity
         */
        Route::post(
            'verify-pin',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->verifyPin($request);
            }
        );

        /*
         * Verify Family Member PIN - verify PIN for any family member
         * Used by user picker to verify parent/child PINs before switching profiles
         * Requires authenticated user (must be in same family)
         */
        Route::post(
            'verify-family-member-pin',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->verifyFamilyMemberPin($request);
            }
        );

        /*
         * OAuth Providers - get list of enabled OAuth providers
         * Returns which social login options are configured (Google, Facebook, GitHub)
         */
        Route::get(
            'oauth-providers',
            static function () {
                return (new \Golem15\User\Controllers\ApiController())->oauthProviders();
            }
        );

        /*
         * Device Management - requires JWT authentication
         * List, revoke, and authorize devices
         */
        Route::get(
            'devices',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->listDevices($request);
            }
        );
        Route::delete(
            'devices/{id}',
            static function (Request $request, $id) {
                return (new \Golem15\User\Controllers\ApiController())->revokeDevice($request, (int)$id);
            }
        )->where('id', '[0-9]+');
        Route::post(
            'devices/authorize',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->authorizeDevice($request);
            }
        );

        /*
         * Device Authorization Flow - for new devices to get QR/code and poll status
         * These can be called without auth (new device doesn't have token yet)
         */
        Route::post(
            'devices/initiate',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->initiateDeviceAuth($request);
            }
        );
        Route::get(
            'devices/status/{token}',
            static function (Request $request, $token) {
                return (new \Golem15\User\Controllers\ApiController())->deviceAuthStatus($request, $token);
            }
        );
    });

/*
|--------------------------------------------------------------------------
| OAuth / Social Login Routes
|--------------------------------------------------------------------------
|
| Routes for OAuth authentication with Google, Facebook, GitHub, etc.
| Rate limited to prevent abuse (20 requests per minute per IP).
|
*/

Route::group(['prefix' => 'oauth', 'middleware' => ['web', 'throttle:20,1']], function () {

    // Redirect to OAuth provider
    Route::get('/{provider}', function ($provider) {
        $component = new \Golem15\User\Components\SocialAuth();
        return $component->onRedirectToProvider($provider);
    })->where('provider', 'google|facebook|github');

    // OAuth callback from provider
    Route::get('/{provider}/callback', function ($provider) {
        $component = new \Golem15\User\Components\SocialAuth();
        return $component->onOAuthCallback($provider);
    })->where('provider', 'google|facebook|github');

});

/*
|--------------------------------------------------------------------------
| Batch User Info Endpoint
|--------------------------------------------------------------------------
|
| Returns minimal user info (id, name, avatar_url) for multiple users.
| Used by presence system to display real user names.
|
*/

Route::middleware('jwt.auth')->get(
    '/api/user/batch',
    static function (Request $request) {
        // Parse comma-separated IDs, convert to integers, filter empty/invalid
        $idsParam = $request->get('ids', '');
        $ids = array_filter(
            array_map('intval', explode(',', $idsParam)),
            fn($id) => $id > 0
        );

        // Empty input = empty result (not error)
        if (empty($ids)) {
            return response()->json(['data' => []]);
        }

        // Query users (non-existent IDs silently skipped via whereIn)
        $users = \Golem15\User\Models\User::whereIn('id', $ids)
            ->get()
            ->map(fn($user) => [
                'id' => $user->id,
                'name' => $user->name,
                'avatar_url' => $user->getAvatarThumb(128),
            ]);

        return response()->json(['data' => $users]);
    }
);
