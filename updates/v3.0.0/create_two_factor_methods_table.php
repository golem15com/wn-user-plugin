<?php

namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;

class CreateTwoFactorMethodsTable extends Migration
{
    public function up()
    {
        Schema::create('golem15_user_two_factor_methods', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('user_id')->unsigned();
            $table->string('method', 20);
            $table->boolean('is_enabled')->default(true);
            $table->text('secret')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();

            $table->unique(['user_id', 'method']);
            $table->index(['user_id', 'is_enabled']);

            $table->foreign('user_id')
                ->references('id')
                ->on('users')
                ->onDelete('cascade');
        });
    }

    public function down()
    {
        Schema::dropIfExists('golem15_user_two_factor_methods');
    }
}
