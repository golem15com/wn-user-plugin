<?php namespace Golem15\User\Models;

use Golem15\User\Contracts\UserRepository;
use Illuminate\Support\Facades\Cache;
use PHPOpenSourceSaver\JWTAuth\Contracts\JWTSubject;
use Str;
use Auth;
use Mail;
use Event;
use Config;
use BackendAuth;
use Carbon\Carbon;
use Winter\Storm\Auth\Models\User as UserBase;
use Golem15\User\Models\Settings as UserSettings;
use Winter\Storm\Auth\AuthException;

class User extends UserBase implements JWTSubject
{
    use \Winter\Storm\Database\Traits\SoftDelete;

    /**
     * @var string The database table used by the model.
     */
    protected $table = 'users';

    /**
     * Validation rules
     */
    public $rules = [
        'email'    => 'required|between:6,255|email|unique:users',
        'avatar'   => 'nullable|image|max:4000',
        'username' => 'required|between:2,255|unique:users',
        'password' => 'required:create|between:8,255|confirmed',
        'password_confirmation' => 'required_with:password|between:8,255',
    ];

    /**
     * Custom validation messages for user-friendly errors
     */
    public $customMessages = [
        'password.confirmed' => 'Password confirmation is required.',
    ];

    /**
     * @var array Relations
     */
    public $belongsToMany = [
        'groups' => [UserGroup::class, 'table' => 'users_groups']
    ];

    public $hasMany = [
        'consentAudits' => [ConsentAudit::class, 'key' => 'user_id'],
        'twoFactorMethods' => [TwoFactorMethod::class, 'key' => 'user_id'],
        'webauthnCredentials' => [WebAuthnCredential::class, 'key' => 'user_id'],
        'twoFactorRecoveryCodes' => [TwoFactorRecoveryCode::class, 'key' => 'user_id'],
        'trustedDevices' => [TrustedDevice::class, 'key' => 'user_id'],
    ];

    public $attachOne = [
        'avatar' => \System\Models\File::class
    ];

    /**
     * @var array The attributes that are mass assignable.
     */
    protected $fillable = [
        'name',
        'surname',
        'login',
        'username',
        'email',
        'password',
        'password_confirmation', // Required for validation, purged before save
        'pin',
        'created_ip_address',
        'last_ip_address',
        'is_onboarded',
        'preferred_locale',
        // GDPR consent fields
        'terms_accepted',
        'privacy_accepted',
        'marketing_consent',
        'consent_ip_address',
        'deletion_reason',
    ];

    /**
     * Reset guarded fields, because we use $fillable instead.
     * @var array The attributes that aren't mass assignable.
     */
    protected $guarded = ['*'];


    /**
     * Purge attributes from data set.
     */
    protected $purgeable = ['password_confirmation', 'send_invite'];

    protected $dates = [
        'last_seen',
        'deleted_at',
        'created_at',
        'updated_at',
        'activated_at',
        'last_login',
        'oauth_token_expires_at',
        'oauth_linked_at',
        // PIN system timestamps
        'pin_locked_until',
        'pin_recovery_expires_at',
        // GDPR consent timestamps
        'terms_accepted_at',
        'privacy_accepted_at',
        'marketing_consent_at',
        'cookie_consent_at',
        'deletion_requested_at',
        'deletion_scheduled_for',
    ];

    protected $casts = [
        'is_onboarded' => 'boolean',
        'oauth_profile_data' => 'array',
        'cookie_preferences' => 'array',
        'ui_preferences' => 'array',
        // GDPR consent booleans
        'terms_accepted' => 'boolean',
        'privacy_accepted' => 'boolean',
        'marketing_consent' => 'boolean',
    ];

    public static $loginAttribute = null;

    public function afterSave()
    {
        Cache::forget(UserRepository::CACHE_KEY_PREFIX . $this->id);
    }

    /**
     * Sends the confirmation email to a user, after activating.
     * @param  string $code
     * @return bool
     */
    public function attemptActivation($code)
    {
        if ($this->trashed()) {
            if ($code === $this->activation_code) {
                $this->restore();
            } else {
                return false;
            }
        } else {

            $result = parent::attemptActivation($code);

            if ($result === false) {
                return false;
            }
        }

        Event::fire('golem15.user.activate', [$this]);

        return true;
    }

    /**
     * Attempts to reset a user's password by matching the reset code generated with the user's.
     *
     * If user activation is enabled, the user will be activated as well.
     *
     * @param string $resetCode
     * @param string $newPassword
     * @return bool
     */
    public function attemptResetPassword($resetCode, $newPassword)
    {
        if (!parent::attemptResetPassword($resetCode, $newPassword)) {
            return false;
        }

        if ($this->isActivatedByUser()) {
            $this->activation_code = null;
            $this->is_activated = true;
            $this->activated_at = $this->freshTimestamp();
            $this->forceSave();
        }

        return true;
    }

    /**
     * Converts a guest user to a registered one and sends an invitation notification.
     * @return void
     */
    public function convertToRegistered($sendNotification = true)
    {
        // Already a registered user
        if (!$this->is_guest) {
            return;
        }

        if ($sendNotification) {
            $this->generatePassword();
        }

        $this->is_guest = false;
        $this->save();

        if ($sendNotification) {
            $this->sendInvitation();
        }
    }

    //
    // Permissions
    //

    /**
     * Check if the user has the given frontend permission.
     */
    public function can(string $permission): bool
    {
        return $this->hasAccess($permission);
    }

    /**
     * Merge group permissions (most-positive-wins) then overlay user-level overrides.
     */
    public function getMergedPermissions()
    {
        if (!$this->mergedPermissions) {
            // Step 1: Merge all group permissions (most positive wins)
            $groupPermissions = [];
            foreach ($this->groups as $group) {
                foreach ((array) $group->permissions as $code => $value) {
                    if (!isset($groupPermissions[$code]) || (int) $value > (int) $groupPermissions[$code]) {
                        $groupPermissions[$code] = (int) $value;
                    }
                }
            }

            // Step 2: User-level permissions override group-level
            $this->mergedPermissions = array_merge($groupPermissions, (array) $this->permissions);
        }

        return $this->mergedPermissions;
    }

    //
    // Constructors
    //

    /**
     * Looks up a user by their email address.
     * @return self
     */
    public static function findByEmail($email)
    {
        if (!$email) {
            return;
        }

        return self::where('email', $email)->first();
    }

    //
    // Getters
    //

    /**
     * Gets a code for when the user is persisted to a cookie or session which identifies the user.
     * @return string
     */
    public function getPersistCode()
    {
        $block = UserSettings::get('block_persistence', false);

        if ($block || !$this->persist_code) {
            return parent::getPersistCode();
        }

        return $this->persist_code;
    }

    /**
     * Returns the public image file path to this user's avatar.
     */
    public function getAvatarThumb($size = 25, $options = null)
    {
        if (is_string($options)) {
            $options = ['default' => $options];
        }
        elseif (!is_array($options)) {
            $options = [];
        }

        // Default is "mm" (Mystery man)
        $default = array_get($options, 'default', 'mm');

        if ($this->avatar) {
            return $this->avatar->getThumb($size, $size, $options);
        }
        else {
            return '//www.gravatar.com/avatar/'.
                md5(strtolower(trim($this->email))).
                '?s='.$size.
                '&d='.urlencode($default);
        }
    }

    /**
     * Returns the name for the user's login.
     * @return string
     */
    public function getLoginName()
    {
        if (static::$loginAttribute !== null) {
            return static::$loginAttribute;
        }

        return static::$loginAttribute = UserSettings::get('login_attribute', UserSettings::LOGIN_EMAIL);
    }

    /**
     * Returns the minimum length for a new password from settings.
     * @return int
     */
    public static function getMinPasswordLength()
    {
        $value = Config::get('golem15.user::minPasswordLength', 8);

        // Guard against a non-scalar resolution (e.g. a namespaced config key that
        // resolves to the whole config array under certain plugin-test harnesses).
        // The value is interpolated into a validation rule string, so a non-numeric
        // value would otherwise trigger an "Array to string conversion".
        if (!is_numeric($value)) {
            return 8;
        }

        return (int) $value;
    }

    //
    // Scopes
    //

    public function scopeIsActivated($query)
    {
        return $query->where('is_activated', 1);
    }

    public function scopeFilterByGroup($query, $filter)
    {
        return $query->whereHas('groups', function($group) use ($filter) {
            $group->whereIn('id', $filter);
        });
    }

    //
    // Events
    //

    /**
     * Before validation event
     * @return void
     */
    public function beforeValidate()
    {
        /*
         * Clean up broken avatar file attachments before validation
         * This prevents validation failures when the avatar file is deleted but the record exists
         */
        $this->cleanupBrokenAvatar();

        /*
         * Guests are special
         */
        if ($this->is_guest && !$this->password) {
            $this->generatePassword();
        }

        /*
         * When the username is not used, the email is substituted.
         */
        if (
            (!$this->username) ||
            ($this->isDirty('email') && $this->getOriginal('email') == $this->username)
        ) {
            $this->username = $this->email;
        }

        /*
         * Apply Password Length Settings
         */
        $minPasswordLength = static::getMinPasswordLength();
        $this->rules['password'] = "required:create|between:$minPasswordLength,255|confirmed";
        $this->rules['password_confirmation'] = "required_with:password|between:$minPasswordLength,255";
    }

    /**
     * Clean up broken avatar file attachments
     * Removes orphaned avatar records where the underlying file no longer exists
     * @return void
     */
    protected function cleanupBrokenAvatar()
    {
        try {
            // Check if avatar relation exists but file is missing
            if ($this->avatar && $this->avatar->disk_name) {
                $filePath = $this->avatar->getLocalPath();
                if ($filePath && !file_exists($filePath)) {
                    \Log::warning('User avatar file missing, clearing broken attachment', [
                        'user_id' => $this->id,
                        'user_email' => $this->email,
                        'missing_file' => $filePath
                    ]);
                    // Delete the orphaned file record
                    $this->avatar->delete();
                    // Clear the relation so it doesn't interfere with validation/save
                    $this->reloadRelations('avatar');
                }
            }
        } catch (\Exception $e) {
            // Log but don't fail - this is a cleanup operation
            \Log::error('Failed to cleanup broken avatar', [
                'user_id' => $this->id,
                'error' => $e->getMessage()
            ]);
        }
    }

    /**
     * After create event
     * @return void
     */
    public function afterCreate()
    {
        $this->restorePurgedValues();

        if ($this->send_invite) {
            $this->sendInvitation();
        }
    }

    /**
     * Before login event
     * @return void
     */
    public function beforeLogin()
    {
        if ($this->is_guest) {
            $login = $this->getLogin();
            throw new AuthException(sprintf(
                'Cannot login user "%s" as they are not registered.', $login
            ));
        }

        parent::beforeLogin();
    }

    /**
     * After login event
     * @return void
     */
    public function afterLogin()
    {
        $this->last_login = $this->freshTimestamp();

        if ($this->trashed()) {
            $this->restore();

            Mail::sendTo($this, 'golem15.user::mail.reactivate', [
                'name' => $this->name
            ]);

            Event::fire('golem15.user.reactivate', [$this]);
        }
        else {
            parent::afterLogin();
        }

        // Set user's preferred locale if they have one saved
        if ($this->preferred_locale) {
            try {
                \Winter\Translate\Classes\Translator::instance()->setLocale($this->preferred_locale, true);
            } catch (\Exception $e) {
                // Translator may not be available, ignore
            }
        }

        Event::fire('golem15.user.login', [$this]);
    }

    /**
     * After delete event
     * @return void
     */
    public function afterDelete()
    {
        if ($this->isSoftDelete()) {
            Event::fire('golem15.user.deactivate', [$this]);
            return;
        }

        $this->avatar && $this->avatar->delete();

        parent::afterDelete();
    }

    //
    // Banning
    //

    /**
     * Ban this user, preventing them from signing in.
     * @return void
     */
    public function ban()
    {
        Auth::findThrottleByUserId($this->id)->ban();
    }

    /**
     * Remove the ban on this user.
     * @return void
     */
    public function unban()
    {
        Auth::findThrottleByUserId($this->id)->unban();
    }

    /**
     * Check if the user is banned.
     * @return bool
     */
    public function isBanned()
    {
        $throttle = Auth::createThrottleModel()->where('user_id', $this->id)->first();
        return $throttle ? $throttle->is_banned : false;
    }

    //
    // Suspending
    //

    /**
     * Check if the user is suspended.
     * @return bool
     */
    public function isSuspended()
    {
        return Auth::findThrottleByUserId($this->id)->checkSuspended();
    }

    /**
     * Remove the suspension on this user.
     * @return void
     */
    public function unsuspend()
    {
        Auth::findThrottleByUserId($this->id)->unsuspend();
    }

    //
    // IP Recording and Throttle
    //

    /**
     * Records the last_ip_address to reflect the last known IP for this user.
     * @param string|null $ipAddress
     * @return void
     */
    public function touchIpAddress($ipAddress)
    {
        $this
            ->newQuery()
            ->where('id', $this->id)
            ->update(['last_ip_address' => $ipAddress])
        ;
    }

    /**
     * Returns true if IP address is throttled and cannot register
     * again. Maximum 3 registrations every 60 minutes.
     * @param string|null $ipAddress
     * @return bool
     */
    public static function isRegisterThrottled($ipAddress)
    {
        if (!$ipAddress) {
            return false;
        }

        $timeLimit = Carbon::now()->subMinutes(60);
        $count = static::make()
            ->where('created_ip_address', $ipAddress)
            ->where('created_at', '>', $timeLimit)
            ->count()
        ;

        return $count > 2;
    }

    //
    // Last Seen
    //

    /**
     * Checks if the user has been seen in the last 5 minutes, and if not,
     * updates the last_seen timestamp to reflect their online status.
     * @return void
     */
    public function touchLastSeen()
    {
        if ($this->isOnline()) {
            return;
        }

        $oldTimestamps = $this->timestamps;
        $this->timestamps = false;

        $this
            ->newQuery()
            ->where('id', $this->id)
            ->update(['last_seen' => $this->freshTimestamp()])
        ;

        $this->last_seen = $this->freshTimestamp();
        $this->timestamps = $oldTimestamps;
    }

    /**
     * Returns true if the user has been active within the last 5 minutes.
     * @return bool
     */
    public function isOnline()
    {
        return $this->getLastSeen() > $this->freshTimestamp()->subMinutes(5);
    }

    /**
     * Returns the date this user was last seen.
     * @return Carbon\Carbon
     */
    public function getLastSeen()
    {
        return $this->last_seen ?: $this->created_at;
    }

    //
    // Utils
    //

    /**
     * Returns the variables available when sending a user notification.
     * @return array
     */
    public function getNotificationVars()
    {
        $vars = [
            'name'     => $this->name,
            'email'    => $this->email,
            'username' => $this->username,
            'login'    => $this->getLogin(),
        ];

        /*
         * Extensibility
         */
        $results = Event::fire('golem15.user.getNotificationVars', [$this]);
        if ($results && is_array($results)) {
            $tempResults = [];
            foreach ($results as $result) {
                if ($result && is_array($result)) {
                    $tempResults = array_merge($tempResults, $result);
                }
            }
            $vars = $tempResults + $vars;
        }

        return $vars;
    }

    /**
     * Sends an invitation to the user using template "golem15.user::mail.invite".
     * @return void
     */
    protected function sendInvitation()
    {
        // AUTH-08: Generate signed activation URL (expires in 72 hours)
        $activationUrl = \URL::temporarySignedRoute(
            'user.activate',
            now()->addHours(72),
            ['id' => $this->id]
        );

        $vars = $this->getNotificationVars();
        $vars['activation_url'] = $activationUrl;

        Mail::sendTo($this, 'golem15.user::mail.invite', $vars);
    }

    /**
     * Assigns this user with a random password.
     * @return void
     */
    protected function generatePassword()
    {
        $this->password = $this->password_confirmation = Str::random(static::getMinPasswordLength());
    }

    //
    // Impersonation
    //

    /**
     * Check if this user can be impersonated by the provided impersonator
     * Only backend users with the `golem15.users.impersonate_user` permission are allowed to impersonate
     * users.
     *
     * @param \Winter\Storm\Auth\Models\User|false $impersonator The user attempting to impersonate this user, false when not available
     * @return boolean
     */
    public function canBeImpersonated($impersonator = false)
    {
        $user = BackendAuth::getUser();
        if (!$user || !$user->hasAccess('golem15.users.impersonate_user')) {
            return false;
        }

        return true;
    }

    /**
     * Determines if activation is done by the user.
     */
    public function isActivatedByUser(): bool
    {
        return (UserSettings::get('activate_mode') === UserSettings::ACTIVATE_USER);
    }

    #[\Override] public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    #[\Override] public function getJWTCustomClaims()
    {
        return [];
    }

    //
    // OAuth / Social Login
    //

    /**
     * Check if this user has an OAuth provider linked
     * @param string|null $provider Check for specific provider (google, facebook, etc.)
     * @return boolean
     */
    public function hasOAuthProvider($provider = null)
    {
        if (!$this->oauth_provider) {
            return false;
        }

        if ($provider === null) {
            return true;
        }

        return $this->oauth_provider === $provider;
    }

    /**
     * Get the display name for the OAuth provider
     * @return string|null
     */
    public function getOAuthProviderName()
    {
        if (!$this->oauth_provider) {
            return null;
        }

        $providers = [
            'google' => 'Google',
            'facebook' => 'Facebook',
            'github' => 'GitHub',
        ];

        return $providers[$this->oauth_provider] ?? ucfirst($this->oauth_provider);
    }

    /**
     * Link an OAuth provider to this user account
     * @param string $provider Provider name (google, facebook, etc.)
     * @param string $providerId Unique ID from the provider
     * @param array $tokens Array with 'token' and optionally 'refreshToken', 'expiresIn'
     * @param array $profileData Additional profile data from provider
     * @return void
     * @throws \Exception if account already linked to different user
     */
    public function linkOAuthProvider($provider, $providerId, $tokens, $profileData = [])
    {
        // Check if this OAuth account is already linked to another user
        $existingUser = static::where('oauth_provider', $provider)
            ->where('oauth_provider_id', $providerId)
            ->where('id', '!=', $this->id)
            ->first();

        if ($existingUser) {
            throw new \Exception(
                Lang::get('golem15.user::lang.oauth.account_already_linked')
            );
        }

        // Encrypt tokens for security
        $this->oauth_provider = $provider;
        $this->oauth_provider_id = $providerId;
        $this->oauth_access_token = encrypt($tokens['token']);

        if (isset($tokens['refreshToken'])) {
            $this->oauth_refresh_token = encrypt($tokens['refreshToken']);
        }

        if (isset($tokens['expiresIn'])) {
            $this->oauth_token_expires_at = Carbon::now()->addSeconds($tokens['expiresIn']);
        }

        $this->oauth_profile_data = $profileData;
        $this->oauth_linked_at = Carbon::now();

        $this->save();

        \Log::info('OAuth account linked', [
            'user_id' => $this->id,
            'provider' => $provider,
            'email' => $this->email
        ]);
    }

    /**
     * Unlink OAuth provider from this user account
     * @return void
     */
    public function unlinkOAuthProvider()
    {
        $provider = $this->oauth_provider;

        $this->oauth_provider = null;
        $this->oauth_provider_id = null;
        $this->oauth_access_token = null;
        $this->oauth_refresh_token = null;
        $this->oauth_token_expires_at = null;
        $this->oauth_profile_data = null;
        $this->oauth_linked_at = null;

        $this->save();

        \Log::info('OAuth account unlinked', [
            'user_id' => $this->id,
            'provider' => $provider,
            'email' => $this->email
        ]);
    }

    /**
     * Get decrypted OAuth access token
     * @return string|null
     */
    public function getOAuthAccessToken()
    {
        if (!$this->oauth_access_token) {
            return null;
        }

        try {
            return decrypt($this->oauth_access_token);
        } catch (\Exception $e) {
            \Log::error('Failed to decrypt OAuth access token', [
                'user_id' => $this->id,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    /**
     * Get decrypted OAuth refresh token
     * @return string|null
     */
    public function getOAuthRefreshToken()
    {
        if (!$this->oauth_refresh_token) {
            return null;
        }

        try {
            return decrypt($this->oauth_refresh_token);
        } catch (\Exception $e) {
            \Log::error('Failed to decrypt OAuth refresh token', [
                'user_id' => $this->id,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    /**
     * Check if OAuth token is expired
     * @return boolean
     */
    public function isOAuthTokenExpired()
    {
        if (!$this->oauth_token_expires_at) {
            return false;
        }

        return Carbon::now()->isAfter($this->oauth_token_expires_at);
    }

    /**
     * Find user by OAuth provider credentials
     * @param string $provider Provider name (google, facebook, etc.)
     * @param string $providerId Unique ID from the provider
     * @return static|null
     */
    public static function findByOAuthProvider($provider, $providerId)
    {
        return static::where('oauth_provider', $provider)
            ->where('oauth_provider_id', $providerId)
            ->first();
    }

    //
    // GDPR Compliance Methods
    //

    /**
     * Record user consent with full audit trail (GDPR Article 7)
     *
     * @param string $termsVersion Version of Terms of Use accepted
     * @param string $privacyVersion Version of Privacy Policy accepted
     * @param string|null $ipAddress IP address (defaults to request IP)
     * @param string|null $userAgent User agent string (defaults to request user agent)
     * @return void
     */
    public function recordConsent($termsVersion, $privacyVersion, $ipAddress = null, $userAgent = null)
    {
        $this->terms_accepted = true;
        $this->terms_accepted_at = now();
        $this->terms_version = $termsVersion;
        $this->privacy_accepted = true;
        $this->privacy_accepted_at = now();
        $this->privacy_version = $privacyVersion;
        $this->consent_ip_address = $ipAddress ?? request()->ip();
        $this->save();

        // Create audit records for terms
        ConsentAudit::create([
            'user_id' => $this->id,
            'consent_type' => ConsentAudit::CONSENT_TYPE_TERMS,
            'action' => ConsentAudit::ACTION_GRANTED,
            'policy_version' => $termsVersion,
            'ip_address' => $this->consent_ip_address,
            'user_agent' => $userAgent ?? request()->userAgent(),
        ]);

        // Create audit record for privacy
        ConsentAudit::create([
            'user_id' => $this->id,
            'consent_type' => ConsentAudit::CONSENT_TYPE_PRIVACY,
            'action' => ConsentAudit::ACTION_GRANTED,
            'policy_version' => $privacyVersion,
            'ip_address' => $this->consent_ip_address,
            'user_agent' => $userAgent ?? request()->userAgent(),
        ]);

        \Log::info("User consent recorded", [
            'user_id' => $this->id,
            'email' => $this->email,
            'terms_version' => $termsVersion,
            'privacy_version' => $privacyVersion,
            'ip' => $this->consent_ip_address,
        ]);
    }

    /**
     * Check if user has accepted current policy versions
     *
     * @param string $currentTermsVersion Current Terms of Use version
     * @param string $currentPrivacyVersion Current Privacy Policy version
     * @return bool
     */
    public function hasCurrentConsent($currentTermsVersion, $currentPrivacyVersion)
    {
        return $this->terms_accepted
            && $this->privacy_accepted
            && $this->terms_version === $currentTermsVersion
            && $this->privacy_version === $currentPrivacyVersion;
    }

    /**
     * Withdraw marketing consent (GDPR Article 7(3))
     *
     * @return void
     */
    public function withdrawMarketingConsent()
    {
        if (!$this->marketing_consent) {
            return;
        }

        $this->marketing_consent = false;
        $this->save();

        ConsentAudit::create([
            'user_id' => $this->id,
            'consent_type' => ConsentAudit::CONSENT_TYPE_MARKETING,
            'action' => ConsentAudit::ACTION_WITHDRAWN,
            'ip_address' => request()->ip(),
            'user_agent' => request()->userAgent(),
        ]);

        \Log::info("Marketing consent withdrawn", ['user_id' => $this->id]);
    }

    /**
     * Check if user has accepted current cookie policy version
     *
     * @return bool
     */
    public function hasCurrentCookieConsent()
    {
        $currentVersion = \Config::get('golem15.user::gdpr.cookie_consent.current_version');

        return $this->cookie_consent_at
            && $this->cookie_consent_version === $currentVersion;
    }

    /**
     * Get user's cookie preference for a specific category
     *
     * @param string $category Category name (essential, analytics, marketing)
     * @return bool
     */
    public function getCookiePreference($category)
    {
        if (!$this->cookie_preferences) {
            // Default: only essential cookies accepted
            return $category === 'essential';
        }

        return $this->cookie_preferences[$category] ?? false;
    }

    /**
     * Update cookie preferences with audit trail
     *
     * @param array $preferences Array of preferences (essential, analytics, marketing)
     * @return void
     */
    public function updateCookiePreferences($preferences)
    {
        $currentVersion = \Config::get('golem15.user::gdpr.cookie_consent.current_version');

        $this->cookie_preferences = array_merge($preferences, [
            'accepted_at' => now()->toIso8601String(),
            'version' => $currentVersion,
        ]);
        $this->cookie_consent_at = now();
        $this->cookie_consent_version = $currentVersion;
        $this->save();

        // Create audit trail
        ConsentAudit::create([
            'user_id' => $this->id,
            'consent_type' => ConsentAudit::CONSENT_TYPE_COOKIES,
            'action' => ConsentAudit::ACTION_GRANTED,
            'policy_version' => $currentVersion,
            'ip_address' => request()->ip(),
            'user_agent' => request()->userAgent(),
            'metadata' => ['preferences' => $preferences],
        ]);

        \Log::info("Cookie preferences updated", [
            'user_id' => $this->id,
            'email' => $this->email,
            'preferences' => $preferences,
            'version' => $currentVersion,
        ]);
    }

    /**
     * Request account deletion with grace period (GDPR Article 17)
     *
     * @param string|null $reason Optional reason for deletion
     * @return void
     * @throws \ApplicationException
     */
    public function requestDeletion($reason = null)
    {
        // Allow plugins to block deletion by throwing.
        Event::fire('golem15.user.requestingDeletion', [$this]);

        $gracePeriodDays = config('gdpr.deletion_grace_period_days', 30);

        $this->deletion_requested_at = now();
        $this->deletion_scheduled_for = now()->addDays($gracePeriodDays);
        $this->deletion_reason = $reason;
        $this->save();

        // Fire event for admin notification
        Event::fire('golem15.user.deletion_requested', [$this]);

        \Log::warning("Account deletion requested", [
            'user_id' => $this->id,
            'email' => $this->email,
            'scheduled_for' => $this->deletion_scheduled_for,
            'reason' => $reason,
        ]);
    }

    /**
     * Cancel pending deletion request
     *
     * @return void
     */
    public function cancelDeletion()
    {
        $this->deletion_requested_at = null;
        $this->deletion_scheduled_for = null;
        $this->deletion_reason = null;
        $this->save();

        \Log::info("Account deletion cancelled", [
            'user_id' => $this->id,
            'email' => $this->email,
        ]);
    }

    /**
     * Permanently delete user and all related data (GDPR Article 17)
     * WARNING: This is irreversible!
     *
     * @param bool $skipFamilyCheck Skip primary parent validation (for cascading child deletions)
     * @return void
     * @throws \ApplicationException
     */
    public function hardDelete($skipFamilyCheck = false)
    {
        \DB::beginTransaction();

        try {
            \Log::warning("Starting hard delete for user", [
                'user_id' => $this->id,
                'email' => $this->email,
            ]);

            // 1. Let plugins run their own cascade/cleanup and
            //    enforce their own guards. Runs inside this transaction, so a
            //    listener throwing rolls the whole deletion back. The
            //    $skipFamilyCheck flag is forwarded for cascaded child deletions.
            Event::fire('golem15.user.deleting', [$this, $skipFamilyCheck]);

            // 2. Delete avatar file
            if ($this->avatar) {
                $this->avatar->delete();
            }

            // 3. Force delete user (bypasses soft delete, triggers DB cascade deletes)
            $this->forceDelete();

            \DB::commit();

            \Log::warning("User hard deleted successfully", [
                'user_id' => $this->id,
                'email' => $this->email,
            ]);

            // Fire audit event
            Event::fire('golem15.user.hard_deleted', [$this->id, $this->email]);

        } catch (\Exception $e) {
            \DB::rollBack();
            \Log::error("Failed to hard delete user", [
                'user_id' => $this->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
            throw $e;
        }
    }

    /**
     * Export user's personal data (GDPR Articles 15 & 20)
     *
     * @return array
     */
    public function exportPersonalData()
    {
        \Log::info("Data export requested", ['user_id' => $this->id]);

        $data = [
            'export_date' => now()->toIso8601String(),
            'export_version' => config('gdpr.export_version', '1.0'),

            'user' => [
                'id' => $this->id,
                'name' => $this->name,
                'surname' => $this->surname,
                'email' => $this->email,
                'username' => $this->username,
                'created_at' => $this->created_at ? $this->created_at->toIso8601String() : null,
                'last_login' => $this->last_login ? $this->last_login->toIso8601String() : null,
                'preferred_locale' => $this->preferred_locale,
                'role' => $this->role ? $this->role->name : null,
            ],

            'consent' => [
                'terms_accepted_at' => $this->terms_accepted_at ? $this->terms_accepted_at->toIso8601String() : null,
                'terms_version' => $this->terms_version,
                'privacy_accepted_at' => $this->privacy_accepted_at ? $this->privacy_accepted_at->toIso8601String() : null,
                'privacy_version' => $this->privacy_version,
                'marketing_consent' => $this->marketing_consent,
                'consent_ip_address' => $this->consent_ip_address,
                'consent_history' => $this->consentAudits->map(function($audit) {
                    return [
                        'type' => $audit->consent_type,
                        'action' => $audit->action,
                        'version' => $audit->policy_version,
                        'date' => $audit->created_at->toIso8601String(),
                    ];
                }),
            ],

            'two_factor_authentication' => [
                'methods' => $this->twoFactorMethods()->where('is_enabled', true)->get()->map(function ($method) {
                    return [
                        'method' => $method->method,
                        'enabled_at' => $method->created_at?->toIso8601String(),
                        'last_used_at' => $method->last_used_at?->toIso8601String(),
                    ];
                }),
                'webauthn_credentials' => $this->webauthnCredentials()->where('is_enabled', true)->get()->map(function ($cred) {
                    return [
                        'name' => $cred->name,
                        'registered_at' => $cred->created_at?->toIso8601String(),
                        'last_used_at' => $cred->last_used_at?->toIso8601String(),
                    ];
                }),
                'recovery_codes_remaining' => $this->twoFactorRecoveryCodes()->whereNull('used_at')->count(),
            ],
        ];

        // Let plugins append their own export sections (each listener returns
        // an associative array of extra sections to merge in).
        $sections = Event::fire('golem15.user.exportPersonalData', [$this], false);
        foreach ((array) $sections as $section) {
            if (is_array($section)) {
                $data = array_merge($data, $section);
            }
        }

        Event::fire('golem15.user.data_exported', [$this]);

        return $data;
    }
}
