<?php namespace Golem15\User\Components;

use Auth;
use Lang;
use Flash;
use Event;
use Request;
use Redirect;
use Exception;
use ValidationException;
use ApplicationException;
use Cms\Classes\Page;
use Cms\Classes\ComponentBase;
use Golem15\User\Models\User as UserModel;
use Golem15\User\Models\UserGroup;
use Golem15\User\Models\Settings as UserSettings;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Contracts\User as SocialiteUser;

/**
 * Social Authentication Component
 *
 * Provides OAuth/social login functionality (Google, Facebook, GitHub, etc.)
 * Supports new registrations, existing user login, and account linking.
 */
class SocialAuth extends ComponentBase
{
    public function componentDetails()
    {
        return [
            'name' => 'golem15.user::lang.socialauth.component_name',
            'description' => 'golem15.user::lang.socialauth.component_desc'
        ];
    }

    public function defineProperties()
    {
        return [
            'redirectAfterAuth' => [
                'title' => 'golem15.user::lang.socialauth.redirect_after_auth',
                'description' => 'golem15.user::lang.socialauth.redirect_after_auth_desc',
                'type' => 'dropdown',
                'default' => 'select'
            ],
            'redirectAfterLink' => [
                'title' => 'golem15.user::lang.socialauth.redirect_after_link',
                'description' => 'golem15.user::lang.socialauth.redirect_after_link_desc',
                'type' => 'dropdown',
                'default' => 'parent/settings'
            ],
        ];
    }

    public function getRedirectAfterAuthOptions()
    {
        return ['select' => 'User Picker (/select)'] + Page::sortBy('baseFileName')->lists('baseFileName', 'baseFileName');
    }

    public function getRedirectAfterLinkOptions()
    {
        return ['parent/settings' => 'Parent Settings', '0' => '- no redirect -'] + Page::sortBy('baseFileName')->lists('baseFileName', 'baseFileName');
    }

    /**
     * Store OAuth consent in session before redirecting to provider
     * AJAX handler called from registration form
     */
    public function onStoreOAuthConsent()
    {
        $termsAccepted = (bool) post('terms_accepted', false);
        $privacyAccepted = (bool) post('privacy_accepted', false);
        $parentalAuthority = (bool) post('parental_authority', false);
        $marketingConsent = (bool) post('marketing_consent', false);
        $betaKey = post('beta_key', '');

        // Store consent in session
        session([
            'oauth_consent' => [
                'terms_accepted' => $termsAccepted,
                'privacy_accepted' => $privacyAccepted,
                'parental_authority' => $parentalAuthority,
                'marketing_consent' => $marketingConsent,
                'beta_key' => $betaKey,
                'timestamp' => now()->timestamp
            ]
        ]);

        \Log::info('OAuth consent stored in session', [
            'terms' => $termsAccepted,
            'privacy' => $privacyAccepted,
            'parental' => $parentalAuthority
        ]);

        return ['success' => true];
    }

    /**
     * Redirect to OAuth provider
     * Called when user clicks "Sign in with Google" button
     */
    public function onRedirectToProvider($provider = null)
    {
        $provider = $provider ?: post('provider', 'google');
        $action = post('action', 'login'); // login, register, link

        // Validate provider
        if (!in_array($provider, ['google', 'facebook', 'github'])) {
            throw new ApplicationException(Lang::get('golem15.user::lang.oauth.invalid_provider'));
        }

        // Check if provider is configured
        if (!$this->isProviderConfigured($provider)) {
            throw new ApplicationException(
                Lang::get('golem15.user::lang.oauth.provider_not_configured', ['provider' => ucfirst($provider)])
            );
        }

        // For linking, verify user is authenticated
        if ($action === 'link' && !Auth::check()) {
            throw new ApplicationException(Lang::get('golem15.user::lang.oauth.must_be_logged_in'));
        }

        // Store action in session for callback
        session(['oauth_action' => $action]);

        // Redirect to provider (stateless for JWT compatibility)
        return Socialite::driver($provider)->stateless()->redirect();
    }

    /**
     * Handle OAuth callback from provider
     * Called by /oauth/{provider}/callback route
     */
    public function onOAuthCallback($provider = null)
    {
        try {
            $provider = $provider ?: $this->property('provider');
            $action = session('oauth_action', 'login');

            // Validate provider
            if (!in_array($provider, ['google', 'facebook', 'github'])) {
                throw new ApplicationException(Lang::get('golem15.user::lang.oauth.invalid_provider'));
            }

            // Get user data from provider
            try {
                $socialiteUser = Socialite::driver($provider)->stateless()->user();
            } catch (\GuzzleHttp\Exception\ClientException $e) {
                // Handle expired/invalid OAuth codes (400 Bad Request with invalid_grant)
                $response = $e->getResponse();
                $body = json_decode($response->getBody()->getContents(), true);

                if (isset($body['error']) && $body['error'] === 'invalid_grant') {
                    \Log::warning('OAuth authorization code expired or invalid', [
                        'provider' => $provider,
                        'error' => $body['error_description'] ?? 'Invalid grant'
                    ]);

                    Flash::error(Lang::get('golem15.user::lang.oauth.code_expired'));
                    return Redirect::to('/login');
                }

                // Other client errors
                \Log::error('OAuth client error', [
                    'provider' => $provider,
                    'status' => $response->getStatusCode(),
                    'error' => $e->getMessage()
                ]);

                Flash::error(Lang::get('golem15.user::lang.oauth.provider_error', ['error' => 'Authentication failed']));
                return Redirect::to('/login');

            } catch (Exception $e) {
                \Log::error('OAuth callback error', [
                    'provider' => $provider,
                    'error' => $e->getMessage()
                ]);

                Flash::error(Lang::get('golem15.user::lang.oauth.provider_error', ['error' => 'Unexpected error']));
                return Redirect::to('/login');
            }

            \Log::info('OAuth callback received', [
                'provider' => $provider,
                'action' => $action,
                'email' => $socialiteUser->getEmail()
            ]);

            // Route to appropriate handler
            switch ($action) {
                case 'login':
                    return $this->handleOAuthLogin($provider, $socialiteUser);

                case 'register':
                    return $this->handleOAuthRegistration($provider, $socialiteUser);

                case 'link':
                    return $this->handleAccountLinking($provider, $socialiteUser);

                default:
                    throw new ApplicationException(Lang::get('golem15.user::lang.oauth.invalid_action'));
            }

        } finally {
            // Clean up session
            session()->forget('oauth_action');
        }
    }

    /**
     * Handle OAuth login for existing user
     */
    protected function handleOAuthLogin($provider, SocialiteUser $socialiteUser)
    {
        // Find user by OAuth provider
        $user = UserModel::findByOAuthProvider($provider, $socialiteUser->getId());

        // If not found, check if email exists and auto-link
        if (!$user) {
            $user = UserModel::where('email', $socialiteUser->getEmail())->first();

            if ($user) {
                // Auto-link OAuth provider to existing account
                \Log::info('Auto-linking OAuth provider to existing account', [
                    'user_id' => $user->id,
                    'provider' => $provider,
                    'email' => $user->email
                ]);
            } else {
                // No account found - automatically register new user
                \Log::info('No account found, auto-registering from OAuth login', [
                    'provider' => $provider,
                    'email' => $socialiteUser->getEmail()
                ]);
                return $this->handleOAuthRegistration($provider, $socialiteUser);
            }
        }

        // Check if user is activated
        if (!$user->is_activated) {
            throw new ApplicationException(Lang::get('golem15.user::lang.account.account_not_activated'));
        }

        // Check if user is banned
        if ($user->isBanned()) {
            throw new ApplicationException(Lang::get('golem15.user::lang.account.account_banned'));
        }

        // Update OAuth tokens
        $user->linkOAuthProvider(
            $provider,
            $socialiteUser->getId(),
            [
                'token' => $socialiteUser->token,
                'refreshToken' => $socialiteUser->refreshToken,
                'expiresIn' => $socialiteUser->expiresIn
            ],
            [
                'name' => $socialiteUser->getName(),
                'email' => $socialiteUser->getEmail(),
                'avatar' => $socialiteUser->getAvatar()
            ]
        );

        // Log the user in
        Auth::login($user, true);

        // Record IP address
        $user->touchIpAddress(Request::ip());

        // Fire login event
        Event::fire('golem15.user.login', [$user]);

        \Log::info('OAuth login successful', [
            'user_id' => $user->id,
            'provider' => $provider,
            'email' => $user->email
        ]);

        // Flash success message
        Flash::success(Lang::get('golem15.user::lang.oauth.login_success'));

        // Redirect to user picker
        $redirectPage = $this->property('redirectAfterAuth', 'select');
        return Redirect::to('/' . ltrim($redirectPage, '/'));
    }

    /**
     * Handle OAuth registration for new user
     */
    protected function handleOAuthRegistration($provider, SocialiteUser $socialiteUser)
    {
        // Check if OAuth account already exists - if so, just login
        $existingOAuthUser = UserModel::findByOAuthProvider($provider, $socialiteUser->getId());
        if ($existingOAuthUser) {
            \Log::info('OAuth registration attempt, but account exists - logging in instead', [
                'user_id' => $existingOAuthUser->id,
                'provider' => $provider
            ]);
            return $this->handleOAuthLogin($provider, $socialiteUser);
        }

        // Check if email already exists - auto-link instead of erroring
        $existingEmailUser = UserModel::where('email', $socialiteUser->getEmail())->first();
        if ($existingEmailUser) {
            \Log::info('OAuth registration with existing email - auto-linking', [
                'user_id' => $existingEmailUser->id,
                'provider' => $provider,
                'email' => $existingEmailUser->email
            ]);

            // Link OAuth and login
            return $this->handleOAuthLogin($provider, $socialiteUser);
        }

        // Check if registration is allowed
        if (!UserSettings::get('allow_registration', true)) {
            throw new ApplicationException(Lang::get('golem15.user::lang.account.registration_disabled'));
        }

        // Check registration throttle
        if ($this->isRegisterThrottled()) {
            throw new ApplicationException(Lang::get('golem15.user::lang.account.registration_throttled'));
        }

        // Validate GDPR consent from session
        $consentData = session('oauth_consent');

        if (!$consentData || !is_array($consentData)) {
            \Log::error('OAuth registration attempted without consent in session', [
                'provider' => $provider,
                'email' => $socialiteUser->getEmail()
            ]);
            Flash::error(Lang::get('golem15.user::lang.gdpr.consent_required'));
            return Redirect::to('/register');
        }

        // Validate consent timestamp (prevent stale consent, max 10 minutes old)
        if (!isset($consentData['timestamp']) || (now()->timestamp - $consentData['timestamp']) > 600) {
            \Log::warning('OAuth registration with expired consent', [
                'provider' => $provider,
                'consent_age' => isset($consentData['timestamp']) ? (now()->timestamp - $consentData['timestamp']) : 'unknown'
            ]);
            session()->forget('oauth_consent');
            Flash::error(Lang::get('golem15.user::lang.gdpr.consent_expired'));
            return Redirect::to('/register');
        }

        // Validate required consents
        if (empty($consentData['terms_accepted']) || empty($consentData['privacy_accepted']) || empty($consentData['parental_authority'])) {
            \Log::error('OAuth registration with incomplete consent', [
                'provider' => $provider,
                'consent' => $consentData
            ]);
            session()->forget('oauth_consent');
            Flash::error(Lang::get('golem15.user::lang.gdpr.consent_required'));
            return Redirect::to('/register');
        }

        // Validate beta key if required
        if (UserSettings::get('require_beta_key', false)) {
            $betaKey = $consentData['beta_key'] ?? '';
            if (!$this->validateBetaKey($betaKey)) {
                \Log::warning('OAuth registration with invalid beta key', [
                    'provider' => $provider
                ]);
                session()->forget('oauth_consent');
                Flash::error(Lang::get('golem15.user::lang.account.beta_key_invalid'));
                return Redirect::to('/register');
            }
        }

        \Log::info('OAuth consent validated successfully', [
            'provider' => $provider,
            'email' => $socialiteUser->getEmail()
        ]);

        // Create new user
        $user = new UserModel();
        $user->email = $socialiteUser->getEmail();
        $user->name = $socialiteUser->getName();

        // Generate username from email or name
        $username = $this->generateUsername($socialiteUser);
        $user->username = $username;

        // Generate random password (required by model, but won't be used)
        $user->password = $user->password_confirmation = \Str::random(16);

        // Auto-activate OAuth users (provider verified email)
        $user->is_activated = true;
        $user->activated_at = \Carbon\Carbon::now();

        // Save user (use forceSave to skip validation since password_confirmation is purgeable)
        // This prevents "password confirmation does not match" error during OAuth registration
        $user->forceSave();

        // Link OAuth provider
        $user->linkOAuthProvider(
            $provider,
            $socialiteUser->getId(),
            [
                'token' => $socialiteUser->token,
                'refreshToken' => $socialiteUser->refreshToken,
                'expiresIn' => $socialiteUser->expiresIn
            ],
            [
                'name' => $socialiteUser->getName(),
                'email' => $socialiteUser->getEmail(),
                'avatar' => $socialiteUser->getAvatar()
            ]
        );

        // Assign to default group (if exists)
        $defaultGroup = UserSettings::get('default_group');
        if ($defaultGroup) {
            $group = UserGroup::find($defaultGroup);
            if ($group) {
                $user->groups()->add($group);
            }
        }

        /*
         * Record GDPR consent for OAuth users
         * Consent was validated and stored in session before OAuth redirect
         */
        $currentPolicyVersion = config('gdpr.current_privacy_version', '2024-12-17');
        $user->recordConsent(
            $currentPolicyVersion,
            $currentPolicyVersion,
            Request::ip(),
            Request::userAgent()
        );

        // Record marketing consent if user opted in
        $marketingConsent = $consentData['marketing_consent'] ?? false;
        if ($marketingConsent) {
            $user->marketing_consent = true;
            $user->marketing_consent_at = now();
            $user->save();

            \Golem15\User\Models\ConsentAudit::create([
                'user_id' => $user->id,
                'consent_type' => \Golem15\User\Models\ConsentAudit::CONSENT_TYPE_MARKETING,
                'action' => \Golem15\User\Models\ConsentAudit::ACTION_GRANTED,
                'ip_address' => Request::ip(),
                'user_agent' => Request::userAgent(),
                'metadata' => json_encode(['oauth_provider' => $provider]),
            ]);
        }

        \Log::info("OAuth registration consent recorded", [
            'user_id' => $user->id,
            'provider' => $provider,
            'marketing_consent' => $marketingConsent
        ]);

        // Clean up consent from session
        session()->forget('oauth_consent');

        // Fire registration event (triggers Family creation in QuestStream)
        Event::fire('golem15.user.register', [$user, []]);

        // Log the user in
        Auth::login($user, true);

        // Record IP address
        $user->touchIpAddress(Request::ip());

        \Log::info('OAuth registration successful', [
            'user_id' => $user->id,
            'provider' => $provider,
            'email' => $user->email
        ]);

        // Flash success message
        Flash::success(Lang::get('golem15.user::lang.oauth.registration_success'));

        // Redirect to user picker or onboarding
        $redirectPage = $this->property('redirectAfterAuth', 'select');
        return Redirect::to('/' . ltrim($redirectPage, '/'));
    }

    /**
     * Handle account linking for authenticated user
     */
    protected function handleAccountLinking($provider, SocialiteUser $socialiteUser)
    {
        $user = Auth::getUser();

        if (!$user) {
            throw new ApplicationException(Lang::get('golem15.user::lang.oauth.must_be_logged_in'));
        }

        // Check if this OAuth account is already linked to another user
        $existingUser = UserModel::findByOAuthProvider($provider, $socialiteUser->getId());
        if ($existingUser && $existingUser->id !== $user->id) {
            throw new ApplicationException(Lang::get('golem15.user::lang.oauth.account_already_linked'));
        }

        // Check if user already has a different provider linked
        if ($user->hasOAuthProvider() && $user->oauth_provider !== $provider) {
            Flash::warning(Lang::get('golem15.user::lang.oauth.replacing_provider', [
                'old' => $user->getOAuthProviderName(),
                'new' => ucfirst($provider)
            ]));
        }

        // Link OAuth provider
        $user->linkOAuthProvider(
            $provider,
            $socialiteUser->getId(),
            [
                'token' => $socialiteUser->token,
                'refreshToken' => $socialiteUser->refreshToken,
                'expiresIn' => $socialiteUser->expiresIn
            ],
            [
                'name' => $socialiteUser->getName(),
                'email' => $socialiteUser->getEmail(),
                'avatar' => $socialiteUser->getAvatar()
            ]
        );

        \Log::info('OAuth account linked', [
            'user_id' => $user->id,
            'provider' => $provider,
            'email' => $user->email
        ]);

        // Flash success message
        Flash::success(Lang::get('golem15.user::lang.oauth.link_success'));

        // Redirect to settings or specified page
        $redirectPage = $this->property('redirectAfterLink', 'parent/settings');
        return Redirect::to('/' . ltrim($redirectPage, '/'));
    }

    /**
     * Unlink OAuth provider from authenticated user
     * AJAX handler called from parent settings
     */
    public function onUnlinkOAuth()
    {
        $user = Auth::getUser();

        if (!$user) {
            throw new ApplicationException(Lang::get('golem15.user::lang.oauth.must_be_logged_in'));
        }

        if (!$user->hasOAuthProvider()) {
            throw new ApplicationException(Lang::get('golem15.user::lang.oauth.no_provider_linked'));
        }

        // Check if user has a password (prevent lockout)
        if (empty($user->password)) {
            throw new ApplicationException(Lang::get('golem15.user::lang.oauth.cannot_unlink_without_password'));
        }

        $provider = $user->getOAuthProviderName();
        $user->unlinkOAuthProvider();

        Flash::success(Lang::get('golem15.user::lang.oauth.unlink_success', ['provider' => $provider]));

        return ['success' => true];
    }

    //
    // Helper Methods
    //

    /**
     * Check if OAuth provider is configured
     */
    protected function isProviderConfigured($provider)
    {
        $config = config("services.{$provider}");

        if (!$config) {
            return false;
        }

        return !empty($config['client_id']) && !empty($config['client_secret']);
    }

    /**
     * Check registration throttle
     */
    protected function isRegisterThrottled()
    {
        if (!UserSettings::get('use_register_throttle', false)) {
            return false;
        }

        return UserModel::isRegisterThrottled(Request::ip());
    }

    /**
     * Generate unique username from OAuth data
     */
    protected function generateUsername(SocialiteUser $socialiteUser)
    {
        // Try email username part first
        $email = $socialiteUser->getEmail();
        if ($email) {
            $baseUsername = strstr($email, '@', true);
        } else {
            // Fallback to name
            $baseUsername = str_replace(' ', '', strtolower($socialiteUser->getName()));
        }

        // Ensure unique
        $username = $baseUsername;
        $counter = 1;

        while (UserModel::where('username', $username)->exists()) {
            $username = $baseUsername . $counter;
            $counter++;
        }

        return $username;
    }
}
