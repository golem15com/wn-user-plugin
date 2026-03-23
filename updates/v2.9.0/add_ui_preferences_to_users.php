<?php

namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Updates\Migration;

class AddUiPreferencesToUsers extends Migration
{
    public function up()
    {
        Schema::table('users', function ($table) {
            $table->json('ui_preferences')->nullable()->after('cookie_preferences');
        });
    }

    public function down()
    {
        Schema::table('users', function ($table) {
            $table->dropColumn('ui_preferences');
        });
    }
}
