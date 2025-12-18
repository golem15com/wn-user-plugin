<?php namespace Golem15\User\Components;

use Auth;
use Config;
use Request;
use Cms\Classes\ComponentBase;
use Golem15\User\Models\User;
use Golem15\User\Models\ConsentAudit;
use Log;

/**
 * Cookie Consent Banner Component
 *
 * GDPR-compliant cookie consent banner with smart display logic.
 * Supports future-proof cookie categories (essential, analytics, marketing)
 * while currently only using essential cookies.
 */
class CookieConsent extends ComponentBase
{
    public function componentDetails()
    {
        return [
            'name' => 'Cookie Consent Banner',
            'description' => 'GDPR-compliant cookie consent banner with smart display logic'
        ];
    }

    public function defineProperties()
    {
        return [
            'mode' => [
                'title' => 'Display Mode',
                'description' => 'Controls when banner is shown',
                'type' => 'dropdown',
                'default' => 'smart',
                'options' => [
                    'disabled' => 'Disabled (never show)',
                    'always' => 'Always show (testing)',
                    'smart' => 'Smart (show when needed)',
                ]
            ],
            'position' => [
                'title' => 'Banner Position',
                'description' => 'Where to display the banner',
                'type' => 'dropdown',
                'default' => 'bottom',
                'options' => [
                    'bottom' => 'Bottom of page',
                    'top' => 'Top of page',
                ]
            ],
        ];
    }

    public function onRun()
    {
        $this->page['mode'] = $this->property('mode', 'smart');
        $this->page['position'] = $this->property('position', 'bottom');
        $this->page['currentVersion'] = $this->getCurrentVersion();
        $this->page['categories'] = $this->getCookieCategories();
        $this->page['shouldShow'] = $this->shouldShowBanner();
        $this->page['isAuthenticated'] = Auth::check();
        $this->page['userConsent'] = $this->getUserConsent();
    }

    /**
     * Get current cookie policy version from config
     *
     * @return string
     */
    protected function getCurrentVersion()
    {
        return Config::get('golem15.user::gdpr.cookie_consent.current_version', '2024-12-17');
    }

    /**
     * Get cookie categories from config
     *
     * @return array
     */
    protected function getCookieCategories()
    {
        return Config::get('golem15.user::gdpr.cookie_consent.categories', []);
    }

    /**
     * Determine if banner should be shown
     *
     * @return bool
     */
    protected function shouldShowBanner()
    {
        $mode = $this->property('mode', 'smart');

        if ($mode === 'disabled') {
            return false;
        }

        if ($mode === 'always') {
            return true;
        }

        // Smart mode logic
        if (Auth::check()) {
            // Authenticated user: check database consent
            $user = Auth::getUser();
            return !$this->hasValidConsent($user);
        } else {
            // Anonymous user: JavaScript will check localStorage
            return true;
        }
    }

    /**
     * Check if user has valid cookie consent
     *
     * @param User $user
     * @return bool
     */
    protected function hasValidConsent($user)
    {
        if (!$user->cookie_consent_at) {
            return false;
        }

        $currentVersion = $this->getCurrentVersion();
        return $user->cookie_consent_version === $currentVersion;
    }

    /**
     * Get user's current consent preferences
     *
     * @return array|null
     */
    protected function getUserConsent()
    {
        if (!Auth::check()) {
            return null;
        }

        $user = Auth::getUser();
        return $user->cookie_preferences ?? [
            'essential' => true,
            'analytics' => false,
            'marketing' => false,
        ];
    }

    /**
     * AJAX: Accept all cookies
     *
     * @return array
     */
    public function onAcceptAll()
    {
        $preferences = [
            'essential' => true,
            'analytics' => true,  // Future-ready
            'marketing' => true,   // Future-ready
        ];

        $this->recordConsent($preferences);

        return [
            'success' => true,
            'message' => 'Cookie preferences saved',
        ];
    }

    /**
     * AJAX: Reject optional cookies (essential only)
     *
     * @return array
     */
    public function onRejectOptional()
    {
        $preferences = [
            'essential' => true,
            'analytics' => false,
            'marketing' => false,
        ];

        $this->recordConsent($preferences);

        return [
            'success' => true,
            'message' => 'Cookie preferences saved',
        ];
    }

    /**
     * AJAX: Save custom preferences
     *
     * @return array
     */
    public function onSavePreferences()
    {
        $preferences = [
            'essential' => true, // Always true
            'analytics' => (bool) post('analytics', false),
            'marketing' => (bool) post('marketing', false),
        ];

        $this->recordConsent($preferences);

        return [
            'success' => true,
            'message' => 'Cookie preferences saved',
        ];
    }

    /**
     * Record cookie consent (database for auth, localStorage for anonymous)
     *
     * @param array $preferences
     * @return void
     */
    protected function recordConsent($preferences)
    {
        $currentVersion = $this->getCurrentVersion();

        if (Auth::check()) {
            // Authenticated user: save to database
            $user = Auth::getUser();
            $user->updateCookiePreferences($preferences);

            Log::info('Cookie consent recorded (authenticated)', [
                'user_id' => $user->id,
                'preferences' => $preferences,
                'version' => $currentVersion,
            ]);
        } else {
            // Anonymous user: JavaScript handles localStorage
            Log::info('Cookie consent recorded (anonymous)', [
                'preferences' => $preferences,
                'version' => $currentVersion,
                'ip' => Request::ip(),
            ]);
        }
    }
}
