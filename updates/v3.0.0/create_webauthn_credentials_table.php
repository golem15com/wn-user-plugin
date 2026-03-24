<?php

namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;

class CreateWebauthnCredentialsTable extends Migration
{
    public function up()
    {
        Schema::create('golem15_user_webauthn_credentials', function (Blueprint $table) {
            $table->increments('id');
            $table->integer('user_id')->unsigned();
            $table->text('credential_id');
            $table->text('public_key');
            $table->string('attestation_type')->nullable();
            $table->json('transports')->nullable();
            $table->integer('sign_count')->unsigned()->default(0);
            $table->string('name')->nullable();
            $table->boolean('is_enabled')->default(true);
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();

            $table->index('user_id');

            $table->foreign('user_id')
                ->references('id')
                ->on('users')
                ->onDelete('cascade');
        });
    }

    public function down()
    {
        Schema::dropIfExists('golem15_user_webauthn_credentials');
    }
}
