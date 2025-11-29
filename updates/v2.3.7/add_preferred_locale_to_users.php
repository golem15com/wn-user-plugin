<?php

namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Updates\Migration;

class AddPreferredLocaleToUsers extends Migration
{
    public function up()
    {
        Schema::table('users', function ($table) {
            $table->string('preferred_locale', 10)->nullable()->after('pin_recovery_expires_at');
        });
    }

    public function down()
    {
        Schema::table('users', function ($table) {
            $table->dropColumn('preferred_locale');
        });
    }
}
