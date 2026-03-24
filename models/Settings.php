<?php namespace Golem15\User\Models;

use Model;

class Settings extends Model
{
    /**
     * @var array Behaviors implemented by this model.
     */
    public $implement = [
        \System\Behaviors\SettingsModel::class
    ];

    public $settingsCode = 'user_settings';
    public $settingsFields = 'fields.yaml';


    const ACTIVATE_AUTO = 'auto';
    const ACTIVATE_USER = 'user';
    const ACTIVATE_ADMIN = 'admin';

    const LOGIN_EMAIL = 'email';
    const LOGIN_USERNAME = 'username';

    const REMEMBER_ALWAYS = 'always';
    const REMEMBER_NEVER = 'never';
    const REMEMBER_ASK = 'ask';

    const TWO_FACTOR_DISABLED = 'disabled';
    const TWO_FACTOR_OPTIONAL = 'optional';
    const TWO_FACTOR_ENFORCED = 'enforced';

    public function initSettingsData()
    {
        $this->require_activation = config('golem15.user::requireActivation', true);
        $this->activate_mode = config('golem15.user::activateMode', self::ACTIVATE_AUTO);
        $this->use_throttle = config('golem15.user::useThrottle', true);
        $this->block_persistence = config('golem15.user::blockPersistence', false);
        $this->allow_registration = config('golem15.user::allowRegistration', true);
        $this->login_attribute = config('golem15.user::loginAttribute', self::LOGIN_EMAIL);
        $this->remember_login = config('golem15.user::rememberLogin', self::REMEMBER_ALWAYS);
        $this->use_register_throttle = config('golem15.user::useRegisterThrottle', true);
        $this->two_factor_mode = config('golem15.user::twoFactorMode', self::TWO_FACTOR_DISABLED);
        $this->two_factor_available_methods = config('golem15.user::twoFactorAvailableMethods', ['totp', 'email']);
        $this->two_factor_email_code_ttl = config('golem15.user::twoFactorEmailCodeTtl', 10);
        $this->two_factor_challenge_ttl = config('golem15.user::twoFactorChallengeTtl', 5);
        $this->two_factor_enforce_groups = config('golem15.user::twoFactorEnforceGroups', []);
        $this->two_factor_passwordless_login = config('golem15.user::twoFactorPasswordlessLogin', false);
        $this->trusted_device_enabled = config('golem15.user::trustedDeviceEnabled', false);
        $this->trusted_device_ttl_days = config('golem15.user::trustedDeviceTtlDays', 30);
    }

    public function getActivateModeOptions()
    {
        return [
            self::ACTIVATE_AUTO => [
                'golem15.user::lang.settings.activate_mode_auto',
                'golem15.user::lang.settings.activate_mode_auto_comment'
            ],
            self::ACTIVATE_USER => [
                'golem15.user::lang.settings.activate_mode_user',
                'golem15.user::lang.settings.activate_mode_user_comment'
            ],
            self::ACTIVATE_ADMIN => [
                'golem15.user::lang.settings.activate_mode_admin',
                'golem15.user::lang.settings.activate_mode_admin_comment'
            ]
        ];
    }

    public function getActivateModeAttribute($value)
    {
        if (!$value) {
            return self::ACTIVATE_AUTO;
        }

        return $value;
    }

    public function getLoginAttributeOptions()
    {
        return [
            self::LOGIN_EMAIL => ['golem15.user::lang.login.attribute_email'],
            self::LOGIN_USERNAME => ['golem15.user::lang.login.attribute_username']
        ];
    }

    public function getRememberLoginOptions()
    {
        return [
            self::REMEMBER_ALWAYS => [
                'golem15.user::lang.settings.remember_always',
            ],
            self::REMEMBER_NEVER => [
                'golem15.user::lang.settings.remember_never',
            ],
            self::REMEMBER_ASK => [
                'golem15.user::lang.settings.remember_ask',
            ]
        ];
    }

    public function getRememberLoginAttribute($value)
    {
        if (!$value) {
            return self::REMEMBER_ALWAYS;
        }

        return $value;
    }

    public function getTwoFactorModeOptions()
    {
        return [
            self::TWO_FACTOR_DISABLED => [
                'golem15.user::lang.settings.two_factor_mode_disabled',
                'golem15.user::lang.settings.two_factor_mode_disabled_comment',
            ],
            self::TWO_FACTOR_OPTIONAL => [
                'golem15.user::lang.settings.two_factor_mode_optional',
                'golem15.user::lang.settings.two_factor_mode_optional_comment',
            ],
            self::TWO_FACTOR_ENFORCED => [
                'golem15.user::lang.settings.two_factor_mode_enforced',
                'golem15.user::lang.settings.two_factor_mode_enforced_comment',
            ],
        ];
    }

    public function getTwoFactorAvailableMethodsOptions()
    {
        return [
            'totp' => 'golem15.user::lang.settings.two_factor_method_totp',
            'webauthn' => 'golem15.user::lang.settings.two_factor_method_webauthn',
            'email' => 'golem15.user::lang.settings.two_factor_method_email',
        ];
    }

    public function getTwoFactorEnforceGroupsOptions()
    {
        return \Golem15\User\Models\UserGroup::lists('name', 'code');
    }

    public function getTwoFactorModeAttribute($value)
    {
        if (!$value) {
            return self::TWO_FACTOR_DISABLED;
        }

        return $value;
    }
}
