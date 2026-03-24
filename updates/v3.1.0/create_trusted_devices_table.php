<?php

namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;

class CreateTrustedDevicesTable extends Migration
{
    public function up()
    {
        Schema::create('golem15_user_trusted_devices', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('user_id')->unsigned();
            $table->string('token', 64)->unique();
            $table->string('device_name')->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->timestamp('trusted_until');
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();

            $table->index('user_id');
            $table->index('token');

            $table->foreign('user_id')
                ->references('id')
                ->on('users')
                ->onDelete('cascade');
        });
    }

    public function down()
    {
        Schema::dropIfExists('golem15_user_trusted_devices');
    }
}
