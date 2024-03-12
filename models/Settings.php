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
}
