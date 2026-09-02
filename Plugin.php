<?php namespace Golem15\User;

use App;
use Auth;
use Event;
use Backend;
use Golem15\User\Contracts\UserRepository;
use Golem15\User\Repositories\UserEloquentRepository;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Factory;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTFactory;
use PHPOpenSourceSaver\JWTAuth\Http\Middleware\RefreshToken;
use Golem15\User\Middleware\JwtAuthenticate;
use Golem15\User\Classes\JwtServiceProvider;
use Golem15\User\Guards\JwtAuthGuard;
use Golem15\User\Guards\JwtAuthGuardServiceProvider;
use Golem15\User\Models\Settings;
use Golem15\User\Models\User;
use System\Classes\PluginBase;
use System\Classes\SettingsManager;
use Illuminate\Foundation\AliasLoader;
use Golem15\User\Classes\UserRedirector;
use Golem15\User\Models\MailBlocker;
use Winter\Notify\Classes\Notifier;

class Plugin extends PluginBase
{
    /**
     * @var boolean Determine if this plugin should have elevated privileges.
     */
    public $elevated = true;

    /**
     * @var array Plugins this plugin depends on.
     */
    public $require = ['Golem15.Apparatus'];

    public function pluginDetails()
    {
        return [
            'name' => 'golem15.user::lang.plugin.name',
            'description' => 'golem15.user::lang.plugin.description',
            'author' => 'Alexey Bobkov, Samuel Georges',
            'icon' => 'icon-user',
            'homepage' => 'https://github.com/wintercms/wn-user-plugin',
            'replaces' => ['RainLab.User' => '~1.6'],
        ];
    }

    public function boot()
    {
        $this->enableAuth();
        $this->bootRepositories();
        // Load GDPR configuration
        \Config::set('gdpr', require __DIR__ . '/config/gdpr.php');
        $this->exceptSpaJwtCookiesFromEncryption();
        $this->applyOAuthSettingsOverrides();
    }

    public function register()
    {
        $this->app->bind(
            AuthManager::class,
            static function ($app) {
                return new AuthManager($app);
            }
        );
        $this->app->singleton(
            'auth',
            static function ($app) {
                return new AuthManager($app);
            }
        );
        $this->app->bind(Factory::class, AuthManager::class);

        $this->app->singleton(\Golem15\User\Classes\TwoFactor\TwoFactorService::class);

        App::singleton('redirect', function ($app) {
            // overrides with our own extended version of Redirector to support
            // seperate url.intended session variable for frontend
            $redirector = new UserRedirector($app['url']);

            // If the session is set on the application instance, we'll inject it into
            // the redirector instance. This allows the redirect responses to allow
            // for the quite convenient "with" methods that flash to the session.
            if (isset($app['session.store'])) {
                $redirector->setSession($app['session.store']);
            }

            return $redirector;
        });

        /*
         * Apply user-based mail blocking
         */
        Event::listen('mailer.prepareSend', function ($mailer, $view, $message) {
            return MailBlocker::filterMessage($view, $message);
        });

        /*
         * Compatability with Winter.Notify
         */
        $this->bindNotificationEvents();

        /*
         * Register Laravel Socialite service provider
         */
        $this->app->register(\Laravel\Socialite\SocialiteServiceProvider::class);

        /*
         * Merge OAuth services configuration
         */
        $this->mergeConfigFrom(
            __DIR__ . '/config/services.php',
            'services'
        );

        $this->publishes(
            [
                base_path() . '/plugins/golem15/user/config/jwt.php' => config_path(
                    'jwt.php'
                ),
                base_path() . '/plugins/golem15/user/config/auth.php' => config_path(
                    'auth.php'
                ),
                base_path() . '/plugins/golem15/user/config/services.php' => config_path(
                    'services.php'
                ),
            ],
            'config'
        );

        /*
         * Register console commands
         */
        $this->registerConsoleCommand('user:process-scheduled-deletions', \Golem15\User\Commands\ProcessScheduledDeletions::class);
        $this->registerConsoleCommand('user:import-permissions', \Golem15\User\Commands\ImportPermissions::class);
    }

    public function registerFormWidgets()
    {
        return [
            \Golem15\User\FormWidgets\FrontendPermissionEditor::class => 'frontendpermissioneditor',
        ];
    }

    public function registerComponents()
    {
        return [
            \Golem15\User\Components\Session::class => 'session',
            \Golem15\User\Components\Account::class => 'account',
            \Golem15\User\Components\ResetPassword::class => 'resetPassword',
            \Golem15\User\Components\DeviceAuth::class => 'deviceAuth',
            \Golem15\User\Components\SocialAuth::class => 'socialAuth',
            \Golem15\User\Components\CookieConsent::class => 'cookieConsent',
            \Golem15\User\Components\TwoFactor::class => 'twoFactor',
        ];
    }

    public function registerPermissions()
    {
        return [
            'golem15.users.access_users' => [
                'tab' => 'golem15.user::lang.plugin.tab',
                'label' => 'golem15.user::lang.plugin.access_users'
            ],
            'golem15.users.access_groups' => [
                'tab' => 'golem15.user::lang.plugin.tab',
                'label' => 'golem15.user::lang.plugin.access_groups'
            ],
            'golem15.users.access_settings' => [
                'tab' => 'golem15.user::lang.plugin.tab',
                'label' => 'golem15.user::lang.plugin.access_settings'
            ],
            'golem15.users.impersonate_user' => [
                'tab' => 'golem15.user::lang.plugin.tab',
                'label' => 'golem15.user::lang.plugin.impersonate_user'
            ],
        ];
    }

    public function registerNavigation()
    {
        return [
            'user' => [
                'label' => 'golem15.user::lang.users.menu_label',
                'url' => Backend::url('golem15/user/users'),
                'icon' => 'icon-user',
                'iconSvg' => 'plugins/golem15/user/assets/images/user-icon.svg',
                'permissions' => ['golem15.users.*'],
                'order' => 555,

                'sideMenu' => [
                    'users' => [
                        'label' => 'golem15.user::lang.users.menu_label',
                        'icon' => 'icon-user',
                        'url' => Backend::url('golem15/user/users'),
                        'permissions' => ['golem15.users.access_users']
                    ],
                    'usergroups' => [
                        'label' => 'golem15.user::lang.groups.menu_label',
                        'icon' => 'icon-users',
                        'url' => Backend::url('golem15/user/usergroups'),
                        'permissions' => ['golem15.users.access_groups']
                    ],
                    'organisations' => [
                        'label' => 'golem15.user::lang.organisation.menu_label',
                        'icon' => 'icon-sitemap',
                        'url' => Backend::url('golem15/user/organisations'),
                        'permissions' => ['golem15.users.access_users']
                    ]
                ]
            ]
        ];
    }

    public function registerSettings()
    {
        return [
            'settings' => [
                'label' => 'golem15.user::lang.settings.menu_label',
                'description' => 'golem15.user::lang.settings.menu_description',
                'category' => SettingsManager::CATEGORY_USERS,
                'icon' => 'icon-cog',
                'class' => 'Golem15\User\Models\Settings',
                'order' => 500,
                'permissions' => ['golem15.users.access_settings']
            ]
        ];
    }

    public function registerMailTemplates()
    {
        return [
            'golem15.user::mail.activate',
            'golem15.user::mail.welcome',
            'golem15.user::mail.restore',
            'golem15.user::mail.new_user',
            'golem15.user::mail.reactivate',
            'golem15.user::mail.invite',
            'golem15.user::mail.two_factor_code',
            'golem15.user::mail.password_bootstrap_code',
            'golem15.user::mail.security_password_changed',
        ];
    }

    public function registerNotificationRules()
    {
        if (!class_exists(\Winter\Notify\Classes\Notifier::class)) {
            return [];
        }

        return [
            'groups' => [
                'user' => [
                    'label' => 'User',
                    'icon' => 'icon-user'
                ],
            ],
            'events' => [
                \Golem15\User\NotifyRules\UserActivatedEvent::class,
                \Golem15\User\NotifyRules\UserRegisteredEvent::class,
            ],
            'actions' => [],
            'conditions' => [
                \Golem15\User\NotifyRules\UserAttributeCondition::class,
            ],
        ];
    }

    protected function bindNotificationEvents()
    {
        if (!class_exists(\Winter\Notify\Classes\Notifier::class)) {
            return;
        }

        Notifier::bindEvents([
            'golem15.user.activate' => \Golem15\User\NotifyRules\UserActivatedEvent::class,
            'golem15.user.register' => \Golem15\User\NotifyRules\UserRegisteredEvent::class,
        ]);

        Notifier::instance()->registerCallback(function ($manager) {
            $manager->registerGlobalParams([
                'user' => Auth::getUser()
            ]);
        });
    }

    private function enableAuth()
    {
        $alias = AliasLoader::getInstance();
        $alias->alias('Auth', 'Golem15\User\Facades\Auth');

        App::singleton('user.auth', function () {
            return \Golem15\User\Classes\AuthManager::instance();
        });

        $this->app->register(JwtServiceProvider::class);
        $facade = AliasLoader::getInstance();
        $facade->alias('JWTAuth', JWTAuth::class);
        $facade->alias('JWTFactory', JWTFactory::class);

        $this->app['auth']->extend('jwt', function ($app, $name, array $config) {
            $guard = new JwtAuthGuard(
                $app['tymon.jwt'],
                $app['auth']->createUserProvider($config['provider']),
                $app['request']
            );
            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });


        $this->app['router']->middleware('jwt.auth', JwtAuthenticate::class);
        $this->app['router']->middleware('jwt.refresh', RefreshToken::class);
        $this->app->register(JwtAuthGuardServiceProvider::class);
        $this->app->bind(AuthManager::class, function ($app) {
            return $this->app['auth'];
        });

        User::extend(
            static function ($model) {
                $model->addDynamicMethod(
                    'getApiArray',
                    static function () use ($model) {
                        $twoFactorService = app(\Golem15\User\Classes\TwoFactor\TwoFactorService::class);
                        $data = [
                            'id' => $model->id,
                            'name' => $model->name,
                            'surname' => $model->surname,
                            'email' => $model->email,
                            'is_activated' => $model->is_activated,
                            'permissions' => $model->permissions,
                            'avatar' => $model->getAvatarThumb(),
                            'avatar_url' => $model->getAvatarThumb(128),
                            'has_avatar' => (bool) $model->avatar,
                            'marketing_consent' => (bool) $model->marketing_consent,
                            'groups' => $model->groups->pluck('name', 'id')->toArray(),
                            'role' => $model->role ? $model->role->slug : null,
                        ];
                        if (isset($model->is_onboarded)) {
                            $data['is_onboarded'] = (bool) $model->is_onboarded;
                        }
                        // k7ut351s: not wrapped in isset() — after migration v3.4.0
                        // the column always exists, and (bool) null would wrongly
                        // read as "no self-set password" on a pre-migration call.
                        // Default to the safe/neutral `true` if the attribute is
                        // ever genuinely absent.
                        $data['has_self_set_password'] = (bool) ($model->has_self_set_password ?? true);
                        // Let plugins contribute extra fields.
                        $extra = \Event::fire('golem15.user.getApiArray', [$model], false);
                        foreach ((array) $extra as $section) {
                            if (is_array($section)) {
                                $data = array_merge($data, $section);
                            }
                        }
                        return $data;
                    }
                );
            }
        );
    }

    private function bootRepositories()
    {
        $this->app->bind(UserRepository::class, UserEloquentRepository::class);
    }

    /**
     * Layer backend-configured OAuth credentials on top of the .env-derived
     * `services.*` config, so Socialite and every provider-config consumer
     * (SocialAuth, Account, ApiController) pick them up transparently. If a
     * provider has no credentials saved in Settings, its .env values are left
     * untouched.
     */
    private function applyOAuthSettingsOverrides(): void
    {
        if (!App::hasDatabase()) {
            return;
        }

        try {
            $settings = Settings::instance();

            foreach (['google', 'facebook', 'github'] as $provider) {
                $clientId = $settings->{$provider . '_client_id'};
                $clientSecret = $settings->{$provider . '_client_secret'};

                if (!empty($clientId) && !empty($clientSecret)) {
                    \Config::set("services.{$provider}.client_id", $clientId);
                    \Config::set("services.{$provider}.client_secret", $clientSecret);
                }
            }
        } catch (\Throwable $e) {
            // system_settings table not migrated yet, or a decrypt failure
            // (e.g. rotated APP_KEY) — fall through and keep the .env values.
        }
    }

    /**
     * SPA JWTs live in JS-set cookies (`auth_token` plus a short-lived `token`
     * mirror for OAuth account linking). Winter EncryptCookies decrypts every
     * cookie not listed here and nulls the value on failure, so
     * resolveAuthenticatedUser() saw nobody on GET /oauth/{provider}?action=link.
     */
    private function exceptSpaJwtCookiesFromEncryption(): void
    {
        \Config::set('cookie.unencryptedCookies', array_values(array_unique(array_merge(
            (array) \Config::get('cookie.unencryptedCookies', []),
            ['token', 'auth_token'],
        ))));
    }
}
