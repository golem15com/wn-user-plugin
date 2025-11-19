<?php

use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;
use Winter\Storm\Support\Facades\Schema;

/**
 * Make user_id nullable in device_auth_sessions table
 * Required for reversed flow where guest devices generate auth sessions
 */
return new class extends Migration
{
    public function up()
    {
        Schema::table('golem15_user_device_auth_sessions', function (Blueprint $table) {
            $table->integer('user_id')->unsigned()->nullable()->change();
        });
    }

    public function down()
    {
        Schema::table('golem15_user_device_auth_sessions', function (Blueprint $table) {
            $table->integer('user_id')->unsigned()->nullable(false)->change();
        });
    }
};
