<?php

use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;
use Winter\Storm\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {
            // Check if columns don't exist before adding
            if (!Schema::hasColumn('users', 'pin_recovery_token')) {
                $table->string('pin_recovery_token', 64)->nullable()->index()->after('is_onboarded');
            }

            if (!Schema::hasColumn('users', 'pin_recovery_expires_at')) {
                $table->timestamp('pin_recovery_expires_at')->nullable()->after('pin_recovery_token');
            }
        });
    }

    public function down()
    {
        Schema::table('users', function (Blueprint $table) {
            if (Schema::hasColumn('users', 'pin_recovery_token')) {
                $table->dropColumn('pin_recovery_token');
            }

            if (Schema::hasColumn('users', 'pin_recovery_expires_at')) {
                $table->dropColumn('pin_recovery_expires_at');
            }
        });
    }
};
