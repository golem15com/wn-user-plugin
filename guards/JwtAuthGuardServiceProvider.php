<?php

namespace Golem15\User\Guards;

use Illuminate\Support\ServiceProvider;
use Golem15\User\Guards\JwtAuthGuard;

class JwtAuthGuardServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        //
    }

    /**
     * Boot the authentication services for the application.
     *
     * @return void
     */
    public function boot()
    {
        auth()->extend('jwt', function ($app, $name, array $config) {
            $guard = new JwtAuthGuard(
                $app['tymon.jwt'],
                $app['auth']->createUserProvider($config['provider']),
                $app['request']
            );
            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }
}
