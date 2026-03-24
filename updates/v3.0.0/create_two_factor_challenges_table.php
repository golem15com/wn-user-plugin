<?php

namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;

class CreateTwoFactorChallengesTable extends Migration
{
    public function up()
    {
        Schema::create('golem15_user_two_factor_challenges', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('user_id')->unsigned();
            $table->string('token', 64)->unique();
            $table->string('method', 20)->nullable();
            $table->string('code', 255)->nullable();
            $table->tinyInteger('attempts')->unsigned()->default(0);
            $table->tinyInteger('max_attempts')->unsigned()->default(5);
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->timestamp('expires_at');
            $table->timestamp('completed_at')->nullable();
            $table->timestamps();

            $table->index('token');
            $table->index(['user_id', 'expires_at']);

            $table->foreign('user_id')
                ->references('id')
                ->on('users')
                ->onDelete('cascade');
        });
    }

    public function down()
    {
        Schema::dropIfExists('golem15_user_two_factor_challenges');
    }
}
