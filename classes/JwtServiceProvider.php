<?php

namespace Golem15\User\Classes;

use Illuminate\Auth\AuthServiceProvider;
use PHPOpenSourceSaver\JWTAuth\Http\Middleware\AuthenticateAndRenew;
use PHPOpenSourceSaver\JWTAuth\Http\Middleware\Check;
use PHPOpenSourceSaver\JWTAuth\Http\Middleware\RefreshToken;
use PHPOpenSourceSaver\JWTAuth\Http\Parser\Cookies;
use PHPOpenSourceSaver\JWTAuth\Http\Parser\RouteParams;
use Golem15\User\Middleware\JwtAuthenticate;
use PHPOpenSourceSaver\JWTAuth\Providers\LaravelServiceProvider;
use Winter\Storm\Support\ServiceProvider;

class JwtServiceProvider extends LaravelServiceProvider
{
    /**
     * The middleware aliases.
     *
     * @var array
     */
    protected array $middlewareAliases = [
        'jwt.auth' => JwtAuthenticate::class,
        'jwt.check' => Check::class,
        'jwt.refresh' => RefreshToken::class,
        'jwt.renew' => AuthenticateAndRenew::class,
    ];

    /**
     * {@inheritdoc}
     */
    public function boot()
    {

        $path = realpath(__DIR__.'/../config/jwt.php');

        $this->publishes([$path => config_path('jwt.php')], 'config');
        $this->mergeConfigFrom($path, 'jwt');

        $this->aliasMiddleware();

        $this->extendAuthGuard();

        $decryptCookies = $this->config('decrypt_cookies');
        $authTokenCookie = new Cookies($decryptCookies);
        $authTokenCookie->setKey('auth_token');

        $this->app['tymon.jwt.parser']->addParser([
            new RouteParams(),
            new Cookies($decryptCookies),
            $authTokenCookie,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function registerStorageProvider()
    {
        $this->app->singleton(
            'tymon.jwt.provider.storage',
            function () {
                $instance = $this->getConfigInstance('providers.storage');

                if (method_exists($instance, 'setLaravelVersion')) {
                    $instance->setLaravelVersion($this->app->version());
                }

                return $instance;
            }
        );
    }

    /**
     * Alias the middleware.
     *
     * @return void
     */
    protected function aliasMiddleware()
    {
        $router = $this->app['router'];

        $method = method_exists($router, 'aliasMiddleware') ? 'aliasMiddleware' : 'middleware';

        foreach ($this->middlewareAliases as $alias => $middleware) {
            $router->$method($alias, $middleware);
        }
    }

    /**
     * Get an instantiable configuration instance.
     *
     * @param string $key
     *
     * @return mixed
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function getConfigInstance($key)
    {
        $instance = $this->config($key);

        if (is_string($instance)) {
            return $this->app->make($instance);
        }

        return $instance;
    }
}
