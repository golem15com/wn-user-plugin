<?php

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

RateLimiter::for('user-api', function (Request $request) {
    return Limit::perMinute(120)->by($request->user()?->id ?: $request->ip());
});

RateLimiter::for('pin-login', function (Request $request) {
    return Limit::perMinute(10)->by($request->ip());
});

RateLimiter::for('2fa-verify', function (Request $request) {
    return Limit::perMinute(10)->by($request->ip());
});

Route::group(
    ['prefix' => '/_user/api/v1', 'middleware' => ['throttle:user-api', 'bindings']],
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
        )->middleware('throttle:pin-login');

        /*
         * Verify PIN - for authenticated users to verify their own PIN
         * Used by parents on user picker to confirm their identity
         */
        Route::post('verify-pin', static function (Request $request) {
            return (new \Golem15\User\Controllers\ApiController())->verifyPin($request);
        })->middleware('throttle:pin-login');

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
        )->middleware('throttle:pin-login');

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
        Route::get(
            'oauth-complete',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->oauthComplete($request);
            }
        );
        Route::post(
            'oauth-register-complete',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->oauthRegisterComplete($request);
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

/*
|--------------------------------------------------------------------------
| Two-Factor Authentication Routes
|--------------------------------------------------------------------------
|
| Challenge routes (unauthenticated, during login flow) and
| management routes (authenticated via JWT).
|
*/

// 2FA Challenge Routes (unauthenticated - during login flow)
Route::group(
    ['prefix' => '/_user/api/v1/2fa', 'middleware' => ['throttle:2fa-verify', 'bindings']],
    static function () {
        Route::post(
            'verify',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->verify($request);
            }
        );
        Route::post(
            'recovery',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->recovery($request);
            }
        );
        Route::post(
            'email/send',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->sendEmailCode($request);
            }
        );
        Route::post(
            'webauthn/options',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->webauthnOptions($request);
            }
        );
        Route::post(
            'webauthn/verify',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->webauthnVerify($request);
            }
        );
    }
);

/*
|--------------------------------------------------------------------------
| User Activation - Signed URL from Invitation Email
|--------------------------------------------------------------------------
|
| Per AUTH-08: replaces plaintext password in invitation.
| The signed URL is verified by Laravel's hasValidSignature().
| Expires after 72 hours (configured in sendInvitation()).
|
*/

Route::get('_user/activate/{id}', function ($id) {
    if (!request()->hasValidSignature()) {
        // Expired or invalid signature
        return redirect('/')->with('error', 'This activation link has expired. Please request a new invitation.');
    }

    $user = \Golem15\User\Models\User::findOrFail($id);

    // Generate a WinterCMS-native reset password code
    // This uses the same mechanism as ResetPassword::onRestorePassword()
    $resetCode = $user->getResetPasswordCode();

    // Build the code in the format expected by ResetPassword component: {userId}!{resetCode}
    $code = implode('!', [$user->id, $resetCode]);

    // Redirect to site root with ?reset= query parameter
    // The ResetPassword component's code() method reads get('reset')
    // and renders the password-set form when a code is present.
    return redirect(url('/') . '?reset=' . $code . '&activate=1');
})->middleware('web')->name('user.activate');

// 2FA Management Routes (authenticated via JWT)
Route::group(
    ['prefix' => '/_user/api/v1/2fa', 'middleware' => ['jwt.auth', 'bindings']],
    static function () {
        Route::get(
            'status',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->status($request);
            }
        );
        Route::post(
            'totp/setup',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->totpSetup($request);
            }
        );
        Route::post(
            'totp/confirm',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->totpConfirm($request);
            }
        );
        Route::delete(
            'totp',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->totpDisable($request);
            }
        );
        Route::post(
            'email/enable',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->emailEnable($request);
            }
        );
        Route::delete(
            'email',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->emailDisable($request);
            }
        );
        Route::post(
            'webauthn/register/options',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->webauthnRegisterOptions($request);
            }
        );
        Route::post(
            'webauthn/register',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->webauthnRegister($request);
            }
        );
        Route::delete(
            'webauthn/{id}',
            static function (Request $request, $id) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->webauthnRemove($request, (int)$id);
            }
        )->where('id', '[0-9]+');
        Route::get(
            'recovery-codes',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->recoveryCodes($request);
            }
        );
        Route::post(
            'recovery-codes/regenerate',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->regenerateRecoveryCodes($request);
            }
        );
        Route::delete(
            'trusted-devices/{id}',
            static function (Request $request, $id) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->trustedDeviceRevoke($request, (int)$id);
            }
        )->where('id', '[0-9]+');
        Route::delete(
            'trusted-devices',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\TwoFactorApiController())->trustedDeviceRevokeAll($request);
            }
        );
    }
);
