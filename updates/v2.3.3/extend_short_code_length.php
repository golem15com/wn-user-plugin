<?php

use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;
use Winter\Storm\Support\Facades\Schema;

/**
 * Extend short_code column length to 9 characters (XXXX-XXXX format)
 */
return new class extends Migration
{
    public function up()
    {
        Schema::table('golem15_user_device_auth_sessions', function (Blueprint $table) {
            $table->string('short_code', 9)->nullable()->change();
        });
    }

    public function down()
    {
        Schema::table('golem15_user_device_auth_sessions', function (Blueprint $table) {
            $table->string('short_code', 8)->nullable()->change();
        });
    }
};
