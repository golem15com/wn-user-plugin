<?php namespace Golem15\User\Tests;

use App;
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
