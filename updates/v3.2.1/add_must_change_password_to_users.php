<?php

namespace Golem15\User\Updates\v3_2_1;

use Schema;
use Winter\Storm\Database\Updates\Migration;

/**
 * Additive: a nullable-boolean "must_change_password" flag on users.
 *
 * Set when an account is created with an admin-supplied temporary password
 * (e.g. an organisation member, Phase 12 / Inventory): the holder must change
 * the password on first login before reaching the app. Defaults false so every
 * existing and self-registered user is unaffected (non-breaking, core plugin).
 */
class AddMustChangePasswordToUsers extends Migration
{
    public function up()
    {
        if (!Schema::hasColumn('users', 'must_change_password')) {
            Schema::table('users', function ($table) {
                $table->boolean('must_change_password')->default(false);
            });
        }
    }

    public function down()
    {
        if (Schema::hasColumn('users', 'must_change_password')) {
            Schema::table('users', function ($table) {
                $table->dropColumn('must_change_password');
            });
        }
    }
}
