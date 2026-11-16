<?php

use Golem15\User\Models\Settings;

return [

    /*
    |--------------------------------------------------------------------------
    | Activation mode
    |--------------------------------------------------------------------------
    |
    | Select how a user account should be activated.
    |
    | ACTIVATE_ADMIN    Administrators must activate users manually.
    | ACTIVATE_AUTO     Users are activated automatically upon registration.
    | ACTIVATE_USER     The user activates their own account using a link sent to them via email.
    |
    */

    'activateMode' => Settings::ACTIVATE_AUTO,

    /*
    |--------------------------------------------------------------------------
    | Headless activation URL
    |--------------------------------------------------------------------------
    |
    | Frontend/SPA URL the activation email should link to. Leave empty to use
    | the built-in backend activation link. Use a ":code" (or "{code}")
    | placeholder for the activation code, e.g.
    | https://www.example.com/user/activate/:code
    |
    */

    'activationUrl' => '',

    /*
    |--------------------------------------------------------------------------
    | Headless password-reset URL
    |--------------------------------------------------------------------------
    |
    | Frontend/SPA URL the password-reset email should link to. Leave empty to
    | use the legacy "/reset-password" link on this app. Use a ":code" (or
    | "{code}") placeholder for the reset code, e.g.
    | https://www.example.com/reset-password?code=:code
    |
    */

    'resetUrl' => '',

    /*
    |--------------------------------------------------------------------------
    | Allow user registration
    |--------------------------------------------------------------------------
    |
    | If this is disabled users can only be created by administrators.
    |
    */

    'allowRegistration' => true,

    /*
    |--------------------------------------------------------------------------
    | Prevent concurrent sessions
    |--------------------------------------------------------------------------
    |
    | When enabled users cannot sign in to multiple devices at the same time.
    |
    */

    'blockPersistence' => false,

    /*
    |--------------------------------------------------------------------------
    | Login attribute
    |--------------------------------------------------------------------------
    |
    | Select what primary user detail should be used for signing in.
    |
    | LOGIN_EMAIL       Authenticate users by email.
    | LOGIN_USERNAME    Authenticate users by username.
    |
    */

    'loginAttribute' => Settings::LOGIN_EMAIL,

    /*
    |--------------------------------------------------------------------------
    | Minimum Password Length
    |--------------------------------------------------------------------------
    |
    | The minimum length of characters required for user passwords.
    |
    */

    'minPasswordLength' => 8,

    /*
    |--------------------------------------------------------------------------
    | Remember login mode
    |--------------------------------------------------------------------------
    |
    | Select if the user session should be persistent.
    |
    | REMEMBER_ALWAYS   Always persist user session.
    | REMEMBER_ASK      Ask if session should be persistent.
    | REMEMBER_NEVER    Never persist user session.
    |
    */

    'rememberLogin' => Settings::REMEMBER_ALWAYS,

    /*
    |--------------------------------------------------------------------------
    | Sign in requires activation
    |--------------------------------------------------------------------------
    |
    | Users must have an activated account to sign in.
    |
    */

    'requireActivation' => true,

    /*
    |--------------------------------------------------------------------------
    | Throttle registration
    |--------------------------------------------------------------------------
    |
    | Prevent multiple registrations from the same IP in short succession.
    |
    */

    'useRegisterThrottle' => true,

    /*
    |--------------------------------------------------------------------------
    | Throttle attempts
    |--------------------------------------------------------------------------
    |
    | Repeat failed sign in attempts will temporarily suspend the user.
    |
    */

    'useThrottle' => true,

    /*
    |--------------------------------------------------------------------------
    | WebAuthn Relying Party ID
    |--------------------------------------------------------------------------
    |
    | The domain every security key / passkey is bound to. Leave empty to use
    | the host of app.url (the behaviour before this key existed). Set it to
    | the registrable domain the browser is on (e.g. "example.com" when the
    | SPA runs on www.example.com and the API on api.example.com).
    |
    | This is a one-way choice: every credential is bound to the RP ID at
    | registration, so changing it later orphans all registered keys.
    |
    */

    'webAuthnRpId' => env('WEBAUTHN_RP_ID', null),

    /*
    |--------------------------------------------------------------------------
    | WebAuthn user verification
    |--------------------------------------------------------------------------
    |
    | "preferred" (default) asks the authenticator for a PIN / biometric but
    | accepts a response without it. "required" asks for it and makes the
    | server reject any response without the user-verified (UV) flag, so
    | U2F-only keys cannot enrol. "discouraged" asks the authenticator not to
    | verify the user.
    |
    */

    'webAuthnUserVerification' => env('WEBAUTHN_USER_VERIFICATION', 'preferred'),

    /*
    |--------------------------------------------------------------------------
    | WebAuthn resident key (discoverable credential)
    |--------------------------------------------------------------------------
    |
    | "required", "preferred" or "discouraged". Leave empty for the default
    | rule: "preferred" when passwordless security-key login is enabled in
    | the User settings, otherwise not requested.
    |
    */

    'webAuthnResidentKey' => env('WEBAUTHN_RESIDENT_KEY', null),
];
