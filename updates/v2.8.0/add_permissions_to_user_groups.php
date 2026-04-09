<?php namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Updates\Migration;

class AddPermissionsToUserGroups extends Migration
{
    public function up()
    {
        Schema::table('user_groups', function ($table) {
            $table->text('permissions')->nullable();
        });
    }

    public function down()
    {
        Schema::table('user_groups', function ($table) {
            $table->dropColumn('permissions');
        });
    }
}
