<?php


use Illuminate\Http\Request;

Route::group(
    ['prefix' => '/_user/api/v1', 'middleware' => ['api']],
    static function () {
        Route::options(
            '{level1?}/{level2?}/{level3?}',
            static function () {
                return Response::make('', 204);
            }
        );
        Route::post(
            'login',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->login($request);
            }
        );
        Route::post(
            'logout',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->logout($request);
            }
        );
        Route::get(
            'fetch',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->fetch();
            }
        );
        Route::post(
            'refresh',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->refresh($request);
            }
        );
        Route::post(
            'register',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->register($request);
            }
        );
        Route::post(
            '/forgot-password',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->forgotPassword($request);
            }
        );

        Route::post(
            '/reset-password',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->resetPassword($request);
            }
        );
        Route::post(
            '/activate',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->activate($request);
            }
        );
        Route::post(
            '/update',
            static function (Request $request) {
                return (new \Golem15\User\Controllers\ApiController())->update($request);
            }
        );
    });
