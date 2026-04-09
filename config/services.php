<?php

/**
 * OAuth/Social Login Services Configuration
 *
 * Configure third-party OAuth providers (Google, Facebook, etc.)
 * for social login functionality in the User plugin.
 *
 * To use Google Sign-In:
 * 1. Create OAuth 2.0 credentials at https://console.cloud.google.com
 * 2. Add authorized redirect URI: {APP_URL}/oauth/google/callback
 * 3. Copy Client ID and Client Secret to .env file
 */

return [

    /*
    |--------------------------------------------------------------------------
    | Google OAuth Configuration
    |--------------------------------------------------------------------------
    |
    | Credentials for Google Sign-In. Create at:
    | https://console.cloud.google.com/apis/credentials
    |
    */
    'google' => [
        'client_id'     => env('GOOGLE_CLIENT_ID'),
        'client_secret' => env('GOOGLE_CLIENT_SECRET'),
        // CMS_URL points to the backend (api.horoskopia.eu) where the /oauth routes live;
        // APP_URL points to the frontend and would produce a 404 on the Nuxt SSR.
        'redirect'      => rtrim(env('CMS_URL', env('APP_URL')), '/') . '/oauth/google/callback',
    ],

    /*
    |--------------------------------------------------------------------------
    | Facebook OAuth Configuration (Optional)
    |--------------------------------------------------------------------------
    |
    | Credentials for Facebook Login. Create at:
    | https://developers.facebook.com/apps
    |
    */
    'facebook' => [
        'client_id'     => env('FACEBOOK_CLIENT_ID'),
        'client_secret' => env('FACEBOOK_CLIENT_SECRET'),
        'redirect'      => rtrim(env('CMS_URL', env('APP_URL')), '/') . '/oauth/facebook/callback',
    ],

    /*
    |--------------------------------------------------------------------------
    | GitHub OAuth Configuration (Optional)
    |--------------------------------------------------------------------------
    |
    | Credentials for GitHub OAuth. Create at:
    | https://github.com/settings/developers
    |
    */
    'github' => [
        'client_id'     => env('GITHUB_CLIENT_ID'),
        'client_secret' => env('GITHUB_CLIENT_SECRET'),
        'redirect'      => rtrim(env('CMS_URL', env('APP_URL')), '/') . '/oauth/github/callback',
    ],

];
