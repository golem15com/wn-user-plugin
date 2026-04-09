<?php namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Updates\Migration;

class CreateFrontendPermissionsTable extends Migration
{
    public function up()
    {
        Schema::create('golem15_user_frontend_permissions', function ($table) {
            $table->increments('id');
            $table->string('code')->unique()->index();
            $table->string('label');
            $table->string('tab');
            $table->string('comment')->nullable();
            $table->timestamps();
        });
    }

    public function down()
    {
        Schema::dropIfExists('golem15_user_frontend_permissions');
    }
}
