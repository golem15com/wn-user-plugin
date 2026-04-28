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
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Contracts\User as SocialiteUser;
use Laravel\Socialite\Two\InvalidStateException;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

/**
 * Social Authentication Component
 *
 * Provides OAuth/social login functionality (Google, Facebook, GitHub, etc.)
 * Supports new registrations, existing user login, and account linking.
 */
class SocialAuth extends ComponentBase
{
    protected const OAUTH_COMPLETE_TTL_MINUTES = 5;
    protected const OAUTH_PENDING_REGISTRATION_TTL_MINUTES = 10;

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
        $action = Request::input('action', post('action', 'login')); // login, register, link

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

        $oauthContext = [
            'mode' => Request::input('mode', 'web'),
            'frontend_callback' => $this->normalizeFrontendCallback(Request::input('frontend_callback')),
            'return_to' => $this->normalizeReturnTo(Request::input('return_to')),
        ];

        session(['oauth_context' => $oauthContext]);

        // Store action in session for callback
        session(['oauth_action' => $action]);

        if ($action === 'register') {
            $consent = [
                'terms_accepted' => (bool) Request::input('terms_accepted', post('terms_accepted', false)),
                'privacy_accepted' => (bool) Request::input('privacy_accepted', post('privacy_accepted', false)),
                'marketing_consent' => (bool) Request::input('marketing_consent', post('marketing_consent', false)),
                'timestamp' => now()->timestamp,
            ];

            if (Request::has('parental_authority') || post('parental_authority') !== null) {
                $consent['parental_authority'] = (bool) Request::input('parental_authority', post('parental_authority', false));
            }

            $betaKey = (string) Request::input('beta_key', post('beta_key', ''));
            if ($betaKey !== '') {
                $consent['beta_key'] = $betaKey;
            }

            session(['oauth_consent' => $consent]);
        }

        // USER-003: Use Socialite's default stateful mode so the OAuth `state`
        // parameter is a session-bound, one-time-use random nonce. Socialite
        // stores the state in the session via the web middleware group (see
        // routes.php OAuth group) and pulls + compares it on callback,
        // throwing InvalidStateException on mismatch. This blocks login-CSRF
        // and link-CSRF replay attacks where an attacker captures their own
        // valid callback URL and tricks a victim into visiting it.
        return Socialite::driver($provider)->redirect();
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

            // Get user data from provider; Socialite (stateful) verifies the
            // session-bound `state` parameter internally and throws
            // InvalidStateException on a CSRF replay (USER-003).
            try {
                $socialiteUser = Socialite::driver($provider)->user();
            } catch (InvalidStateException $e) {
                \Log::warning('OAuth state validation failed (possible CSRF replay)', [
                    'provider' => $provider,
                    'ip' => Request::ip(),
                ]);
                return $this->redirectOAuthError(Lang::get('golem15.user::lang.oauth.invalid_state'));
            } catch (\GuzzleHttp\Exception\ClientException $e) {
                // Handle expired/invalid OAuth codes (400 Bad Request with invalid_grant)
                $response = $e->getResponse();
                $body = json_decode($response->getBody()->getContents(), true);

                if (isset($body['error']) && $body['error'] === 'invalid_grant') {
                    \Log::warning('OAuth authorization code expired or invalid', [
                        'provider' => $provider,
                        'error' => $body['error_description'] ?? 'Invalid grant'
                    ]);

                    return $this->redirectOAuthError(Lang::get('golem15.user::lang.oauth.code_expired'));
                }

                // Other client errors
                \Log::error('OAuth client error', [
                    'provider' => $provider,
                    'status' => $response->getStatusCode(),
                    'error' => $e->getMessage()
                ]);

                return $this->redirectOAuthError(Lang::get('golem15.user::lang.oauth.provider_error', ['error' => 'Authentication failed']));

            } catch (Exception $e) {
                \Log::error('OAuth callback error', [
                    'provider' => $provider,
                    'error' => $e->getMessage()
                ]);

                return $this->redirectOAuthError(Lang::get('golem15.user::lang.oauth.provider_error', ['error' => 'Unexpected error']));
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

        } catch (ApplicationException $e) {
            return $this->redirectOAuthError($e->getMessage());
        } finally {
            // Clean up session
            session()->forget('oauth_action');
            session()->forget('oauth_context');
        }
    }

    /**
     * Handle OAuth login for existing user
     */
    protected function handleOAuthLogin($provider, SocialiteUser $socialiteUser)
    {
        $providerUserId = $this->getProviderUserId($socialiteUser);
        if (!$providerUserId) {
            throw new ApplicationException('Nie udało się odczytać identyfikatora konta z dostawcy logowania.');
        }

        // Find user by OAuth provider
        $user = $providerUserId ? UserModel::findByOAuthProvider($provider, $providerUserId) : null;

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
                if (($this->getOAuthContext()['mode'] ?? 'web') === 'spa') {
                    \Log::info('No account found, redirecting SPA user to pending OAuth registration', [
                        'provider' => $provider,
                        'email' => $socialiteUser->getEmail()
                    ]);
                    return $this->redirectToPendingRegistration($provider, $socialiteUser);
                }

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
            $providerUserId,
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

        return $this->completeSuccessfulAuth(
            $user,
            'login',
            Lang::get('golem15.user::lang.oauth.login_success')
        );
    }

    /**
     * Handle OAuth registration for new user
     */
    protected function handleOAuthRegistration($provider, SocialiteUser $socialiteUser)
    {
        $providerUserId = $this->getProviderUserId($socialiteUser);
        if (!$providerUserId) {
            throw new ApplicationException('Nie udało się odczytać identyfikatora konta z dostawcy logowania.');
        }

        // Check if OAuth account already exists - if so, just login
        $existingOAuthUser = $providerUserId ? UserModel::findByOAuthProvider($provider, $providerUserId) : null;
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
            return $this->redirectOAuthError(Lang::get('golem15.user::lang.gdpr.consent_required'), '/register');
        }

        // Validate consent timestamp (prevent stale consent, max 10 minutes old)
        if (!isset($consentData['timestamp']) || (now()->timestamp - $consentData['timestamp']) > 600) {
            \Log::warning('OAuth registration with expired consent', [
                'provider' => $provider,
                'consent_age' => isset($consentData['timestamp']) ? (now()->timestamp - $consentData['timestamp']) : 'unknown'
            ]);
            session()->forget('oauth_consent');
            return $this->redirectOAuthError(Lang::get('golem15.user::lang.gdpr.consent_expired'), '/register');
        }

        // Validate required consents
        if (
            empty($consentData['terms_accepted'])
            || empty($consentData['privacy_accepted'])
            || (array_key_exists('parental_authority', $consentData) && !$consentData['parental_authority'])
        ) {
            \Log::error('OAuth registration with incomplete consent', [
                'provider' => $provider,
                'consent' => $consentData
            ]);
            session()->forget('oauth_consent');
            return $this->redirectOAuthError(Lang::get('golem15.user::lang.gdpr.consent_required'), '/register');
        }

        // Validate beta key if required
        if (UserSettings::get('require_beta_key', false)) {
            $betaKey = $consentData['beta_key'] ?? '';
            if (!$this->validateBetaKey($betaKey)) {
                \Log::warning('OAuth registration with invalid beta key', [
                    'provider' => $provider
                ]);
                session()->forget('oauth_consent');
                return $this->redirectOAuthError(Lang::get('golem15.user::lang.account.beta_key_invalid'), '/register');
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
        $temporaryPassword = \Str::random(16);
        $user->password = $user->password_confirmation = $temporaryPassword;

        // Auto-activate OAuth users (provider verified email)
        $user->is_activated = true;
        $user->activated_at = \Carbon\Carbon::now();

        // Save user (use forceSave to skip validation since password_confirmation is purgeable)
        // This prevents "password confirmation does not match" error during OAuth registration
        $user->forceSave();

        // Link OAuth provider
        $this->restorePasswordConfirmation($user, $temporaryPassword);
        $user->linkOAuthProvider(
            $provider,
            $providerUserId,
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
        $this->restorePasswordConfirmation($user, $temporaryPassword);
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
            $this->restorePasswordConfirmation($user, $temporaryPassword);
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

        return $this->completeSuccessfulAuth(
            $user,
            'register',
            Lang::get('golem15.user::lang.oauth.registration_success')
        );
    }

    /**
     * Handle account linking for authenticated user
     */
    protected function handleAccountLinking($provider, SocialiteUser $socialiteUser)
    {
        $user = Auth::getUser();
        $providerUserId = $this->getProviderUserId($socialiteUser);
        if (!$providerUserId) {
            throw new ApplicationException('Nie udało się odczytać identyfikatora konta z dostawcy logowania.');
        }

        if (!$user) {
            throw new ApplicationException(Lang::get('golem15.user::lang.oauth.must_be_logged_in'));
        }

        // Check if this OAuth account is already linked to another user
        $existingUser = $providerUserId ? UserModel::findByOAuthProvider($provider, $providerUserId) : null;
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
            $providerUserId,
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
     * Validate beta tester key
     */
    protected function validateBetaKey($inputKey)
    {
        $expectedKey = env('BETATESTER_KEY', '');

        // If no beta key is configured, validation passes
        if (empty($expectedKey)) {
            return true;
        }

        // If no input key provided, validation fails
        if (empty($inputKey)) {
            return false;
        }

        // Use hash_equals for constant-time comparison to prevent timing attacks
        return hash_equals($expectedKey, $inputKey);
    }

    protected function completeSuccessfulAuth(UserModel $user, string $action, string $successMessage)
    {
        $context = $this->getOAuthContext();
        $mode = $context['mode'] ?? 'web';

        if ($mode === 'spa') {
            $frontendCallback = $context['frontend_callback'] ?? null;
            if ($frontendCallback) {
                $code = Str::random(64);
                Cache::put('oauth-complete:' . $code, [
                    'token' => JWTAuth::fromUser($user),
                    'user' => $user->getApiArray(),
                    'action' => $action,
                    'return_to' => $context['return_to'] ?? '/',
                ], now()->addMinutes(self::OAUTH_COMPLETE_TTL_MINUTES));

                session()->forget('oauth_context');
                session()->forget('oauth_consent');

                return Redirect::to($frontendCallback . '?code=' . urlencode($code));
            }
        }

        Flash::success($successMessage);

        $redirectPage = $this->property('redirectAfterAuth', 'select');
        return Redirect::to('/' . ltrim($redirectPage, '/'));
    }

    protected function redirectOAuthError(string $message, string $fallbackPath = '/login')
    {
        $context = $this->getOAuthContext();
        $mode = $context['mode'] ?? 'web';

        if ($mode === 'spa') {
            $frontendCallback = $context['frontend_callback'] ?? null;
            if ($frontendCallback) {
                session()->forget('oauth_context');
                return Redirect::to($frontendCallback . '?error=' . urlencode($message));
            }
        }

        Flash::error($message);
        return Redirect::to($fallbackPath);
    }

    protected function redirectToPendingRegistration(string $provider, SocialiteUser $socialiteUser)
    {
        $context = $this->getOAuthContext();
        $frontendCallback = $context['frontend_callback'] ?? null;
        $providerUserId = $this->getProviderUserId($socialiteUser);

        if (!$frontendCallback) {
            return $this->handleOAuthRegistration($provider, $socialiteUser);
        }

        if (!$providerUserId) {
            return $this->redirectOAuthError('Nie udało się odczytać identyfikatora konta z dostawcy logowania.');
        }

        $pendingCode = Str::random(64);
        Cache::put('oauth-pending-registration:' . $pendingCode, [
            'provider' => $provider,
            'provider_id' => $providerUserId,
            'token' => $socialiteUser->token,
            'refresh_token' => $socialiteUser->refreshToken,
            'expires_in' => $socialiteUser->expiresIn,
            'name' => $socialiteUser->getName(),
            'email' => $socialiteUser->getEmail(),
            'avatar' => $socialiteUser->getAvatar(),
            'return_to' => $context['return_to'] ?? '/',
        ], now()->addMinutes(self::OAUTH_PENDING_REGISTRATION_TTL_MINUTES));

        session()->forget('oauth_context');
        session()->forget('oauth_consent');

        return Redirect::to($frontendCallback . '?pending_registration=' . urlencode($pendingCode));
    }

    protected function getOAuthContext(): array
    {
        $context = session('oauth_context', []);
        return is_array($context) ? $context : [];
    }

    public function completePendingRegistration(array $payload): array
    {
        $provider = $payload['provider'];
        $providerId = $payload['provider_id'];

        $existingOAuthUser = UserModel::findByOAuthProvider($provider, $providerId);
        if ($existingOAuthUser) {
            return $this->buildAuthResultFromExistingUser($existingOAuthUser, $provider, $payload, 'login');
        }

        $email = $payload['email'] ?? null;
        if ($email) {
            $existingEmailUser = UserModel::where('email', $email)->first();
            if ($existingEmailUser) {
                return $this->buildAuthResultFromExistingUser($existingEmailUser, $provider, $payload, 'login');
            }
        }

        if (!UserSettings::get('allow_registration', true)) {
            throw new ApplicationException(Lang::get('golem15.user::lang.account.registration_disabled'));
        }

        if ($this->isRegisterThrottled()) {
            throw new ApplicationException(Lang::get('golem15.user::lang.account.registration_throttled'));
        }

        $user = new UserModel();
        $user->email = $payload['email'] ?? null;
        $user->name = $payload['name'] ?: ($payload['email'] ?? 'User');
        $user->username = $this->generateUsernameFromPayload($payload);
        $temporaryPassword = Str::random(16);
        $user->password = $user->password_confirmation = $temporaryPassword;
        $user->is_activated = true;
        $user->activated_at = \Carbon\Carbon::now();
        $user->forceSave();

        $this->restorePasswordConfirmation($user, $temporaryPassword);
        $this->linkOAuthPayloadToUser($user, $provider, $payload);

        $defaultGroup = UserSettings::get('default_group');
        if ($defaultGroup) {
            $group = UserGroup::find($defaultGroup);
            if ($group) {
                $user->groups()->add($group);
            }
        }

        $currentTermsVersion = config('gdpr.current_terms_version', '2024-12-17');
        $currentPrivacyVersion = config('gdpr.current_privacy_version', '2024-12-17');
        $this->restorePasswordConfirmation($user, $temporaryPassword);
        $user->recordConsent(
            $currentTermsVersion,
            $currentPrivacyVersion,
            Request::ip(),
            Request::userAgent()
        );

        if (!empty($payload['marketing_consent'])) {
            $user->marketing_consent = true;
            $user->marketing_consent_at = now();
            $this->restorePasswordConfirmation($user, $temporaryPassword);
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

        Event::fire('golem15.user.register', [$user, []]);
        Auth::login($user, true);
        $user->touchIpAddress(Request::ip());
        Event::fire('golem15.user.login', [$user]);

        return [
            'token' => JWTAuth::fromUser($user),
            'user' => $user->getApiArray(),
            'action' => 'register',
            'return_to' => $payload['return_to'] ?? '/',
        ];
    }

    protected function buildAuthResultFromExistingUser(UserModel $user, string $provider, array $payload, string $action): array
    {
        if (!$user->is_activated) {
            throw new ApplicationException(Lang::get('golem15.user::lang.account.account_not_activated'));
        }

        if ($user->isBanned()) {
            throw new ApplicationException(Lang::get('golem15.user::lang.account.account_banned'));
        }

        $this->linkOAuthPayloadToUser($user, $provider, $payload);

        Auth::login($user, true);
        $user->touchIpAddress(Request::ip());
        Event::fire('golem15.user.login', [$user]);

        return [
            'token' => JWTAuth::fromUser($user),
            'user' => $user->getApiArray(),
            'action' => $action,
            'return_to' => $payload['return_to'] ?? '/',
        ];
    }

    protected function linkOAuthPayloadToUser(UserModel $user, string $provider, array $payload): void
    {
        $user->linkOAuthProvider(
            $provider,
            $payload['provider_id'],
            [
                'token' => $payload['token'],
                'refreshToken' => $payload['refresh_token'],
                'expiresIn' => $payload['expires_in'],
            ],
            [
                'name' => $payload['name'] ?? null,
                'email' => $payload['email'] ?? null,
                'avatar' => $payload['avatar'] ?? null,
            ]
        );
    }

    protected function restorePasswordConfirmation(UserModel $user, string $password): void
    {
        $user->password = $password;
        $user->password_confirmation = $password;
    }

    protected function getProviderUserId(SocialiteUser $socialiteUser): ?string
    {
        $id = $socialiteUser->getId();
        if (is_scalar($id) && (string) $id !== '') {
            return (string) $id;
        }

        if (method_exists($socialiteUser, 'getRaw')) {
            $raw = $socialiteUser->getRaw();
            foreach (['id', 'sub', 'user_id'] as $key) {
                if (isset($raw[$key]) && (string) $raw[$key] !== '') {
                    return (string) $raw[$key];
                }
            }
        }

        if (property_exists($socialiteUser, 'user') && is_array($socialiteUser->user)) {
            foreach (['id', 'sub', 'user_id'] as $key) {
                if (isset($socialiteUser->user[$key]) && (string) $socialiteUser->user[$key] !== '') {
                    return (string) $socialiteUser->user[$key];
                }
            }
        }

        return null;
    }

    protected function normalizeReturnTo($returnTo): string
    {
        if (!is_string($returnTo) || $returnTo === '') {
            return '/';
        }

        if (!str_starts_with($returnTo, '/')) {
            return '/';
        }

        if (preg_match('#^//#', $returnTo)) {
            return '/';
        }

        return $returnTo;
    }

    protected function normalizeFrontendCallback($callback): ?string
    {
        if (!is_string($callback) || $callback === '') {
            return null;
        }

        $parts = parse_url($callback);
        if ($parts === false) {
            return null;
        }

        $path = $parts['path'] ?? '';
        if ($path !== '/auth/oauth/callback') {
            return null;
        }

        if (!isset($parts['scheme'], $parts['host'])) {
            return '/auth/oauth/callback';
        }

        if (!in_array($parts['scheme'], ['http', 'https'], true)) {
            return null;
        }

        $host = $parts['host'];

        // Build a whitelist of allowed frontend origins. In split-domain deployments
        // (e.g. frontend on horoskopia.eu, backend on api.horoskopia.eu) the request
        // host differs from the frontend host, so APP_URL (the frontend) is the
        // authoritative source. Localhost is always allowed for dev.
        $allowedHosts = ['localhost', '127.0.0.1'];
        if ($requestHost = parse_url(Request::root(), PHP_URL_HOST)) {
            $allowedHosts[] = $requestHost;
        }
        if ($appHost = parse_url((string) env('APP_URL'), PHP_URL_HOST)) {
            $allowedHosts[] = $appHost;
        }

        if (!in_array($host, $allowedHosts, true)) {
            return null;
        }

        $port = isset($parts['port']) ? ':' . $parts['port'] : '';
        return $parts['scheme'] . '://' . $host . $port . $path;
    }

    protected function generateUsernameFromPayload(array $payload): string
    {
        $email = $payload['email'] ?? null;
        if (is_string($email) && $email !== '') {
            $baseUsername = strstr($email, '@', true);
        } else {
            $name = trim((string) ($payload['name'] ?? 'user'));
            $baseUsername = str_replace(' ', '', strtolower($name));
        }

        $baseUsername = preg_replace('/[^a-z0-9_\-]/', '', strtolower($baseUsername ?? 'user')) ?: 'user';
        $username = $baseUsername;
        $counter = 1;

        while (UserModel::where('username', $username)->exists()) {
            $username = $baseUsername . $counter;
            $counter++;
        }

        return $username;
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
