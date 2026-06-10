<?php namespace Golem15\User\Tests;

use App;
use Config;
use Illuminate\Foundation\AliasLoader;
use Golem15\User\Models\Settings;

abstract class UserPluginTestCase extends \PluginTestCase
{
    /**
     * @var array   Plugins to refresh between tests.
     */
    protected $refreshPlugins = [
        'Winter.User',
    ];

    /**
     * Perform test case set up.
     *
     * @return void
     */
    public function setUp(): void
    {
        parent::setUp();

        // Provide a deterministic JWT secret so controller paths that mint a token
        // (e.g. activate-and-sign-in) run under the plain-phpunit harness. Production
        // always has a configured secret via `php artisan jwt:secret`; without one the
        // jwt-auth provider throws SecretMissingException. Test-only, behaviour-neutral.
        if (!Config::get('jwt.secret')) {
            Config::set('jwt.secret', 'testing-only-deterministic-jwt-secret-key-0001');
        }

        // reset any modified settings
        Settings::resetDefault();

        // log out after each test
        \Golem15\User\Classes\AuthManager::instance()->logout();

        // register the auth facade
        $alias = AliasLoader::getInstance();
        $alias->alias('Auth', 'Golem15\User\Facades\Auth');

        App::singleton('user.auth', function () {
            return \Golem15\User\Classes\AuthManager::instance();
        });
    }
}
