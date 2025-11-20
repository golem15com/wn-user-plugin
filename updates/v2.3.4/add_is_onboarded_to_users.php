<?php

namespace Golem15\User\Updates\v2_3_4;

use Schema;
use Winter\Storm\Database\Updates\Migration;
use Illuminate\Support\Facades\DB;

class AddIsOnboardedToUsers extends Migration
{
    public function up()
    {
        if (!Schema::hasColumn('users', 'is_onboarded')) {
            Schema::table('users', function ($table) {
                $table->boolean('is_onboarded')->default(false)->index();
            });

            // Mark existing users as onboarded to avoid blocking them
            DB::table('users')->update(['is_onboarded' => true]);
        }
    }

    public function down()
    {
        if (Schema::hasColumn('users', 'is_onboarded')) {
            Schema::table('users', function ($table) {
                $table->dropColumn('is_onboarded');
            });
        }
    }
}
