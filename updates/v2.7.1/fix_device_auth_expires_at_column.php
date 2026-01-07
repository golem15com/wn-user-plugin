<?php

namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Updates\Migration;

/**
 * Fix DeviceAuthSession expires_at column
 *
 * Removes automatic timestamp behavior that was corrupting the expires_at field
 */
class FixDeviceAuthExpiresAtColumn extends Migration
{
    public function up()
    {
        Schema::table('golem15_user_device_auth_sessions', function ($table) {
            // Change expires_at to nullable without automatic timestamp behavior
            $table->dateTime('expires_at')->nullable()->change();
        });
    }

    public function down()
    {
        Schema::table('golem15_user_device_auth_sessions', function ($table) {
            // Revert to original definition
            $table->timestamp('expires_at')->change();
        });
    }
}
