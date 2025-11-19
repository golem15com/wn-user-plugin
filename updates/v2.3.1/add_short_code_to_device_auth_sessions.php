<?php

use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;
use Winter\Storm\Support\Facades\Schema;

/**
 * Add short_code column to device_auth_sessions table
 * For HBO-style 8-character authorization codes
 */
return new class extends Migration
{
    public function up()
    {
        Schema::table('golem15_user_device_auth_sessions', function (Blueprint $table) {
            $table->string('short_code', 9)->nullable()->unique()->after('token');
        });
    }

    public function down()
    {
        Schema::table('golem15_user_device_auth_sessions', function (Blueprint $table) {
            $table->dropColumn('short_code');
        });
    }
};
