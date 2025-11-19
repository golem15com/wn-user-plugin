<?php

namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Updates\Migration;

/**
 * CreateDeviceAuthSessionsTable Migration
 *
 * Creates table for QR code-based device authorization sessions.
 * Allows parents to authorize new devices by scanning a QR code.
 */
class CreateDeviceAuthSessionsTable extends Migration
{
    public function up()
    {
        Schema::create('golem15_user_device_auth_sessions', function ($table) {
            $table->increments('id');
            $table->string('token', 64)->unique()->index();
            $table->integer('user_id')->unsigned()->index();
            $table->enum('status', ['pending', 'confirmed', 'used', 'expired', 'revoked'])->default('pending')->index();
            $table->timestamp('expires_at')->index();

            // Device information from the NEW device requesting authorization
            $table->string('device_ip')->nullable();
            $table->text('device_user_agent')->nullable();
            $table->string('device_name')->nullable(); // User-friendly name (optional)

            // Authorization information from the AUTHORIZING device
            $table->string('auth_ip')->nullable(); // IP that confirmed the auth
            $table->timestamp('confirmed_at')->nullable();
            $table->timestamp('used_at')->nullable(); // When session was actually used to login

            // Session tracking
            $table->string('session_id')->nullable(); // Winter session ID created for new device
            $table->timestamp('last_activity_at')->nullable();

            $table->timestamps();

            $table->foreign('user_id')
                ->references('id')
                ->on('users')
                ->onDelete('cascade');
        });
    }

    public function down()
    {
        Schema::dropIfExists('golem15_user_device_auth_sessions');
    }
}