<?php

use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;
use Winter\Storm\Support\Facades\Schema;

/**
 * Device-flow redeem for API clients (additive).
 *
 * code_challenge: PKCE S256 challenge (RFC 7636) sent by a client that wants to
 * redeem a JWT itself. A session with a challenge is "redeemable"; sessions
 * without one behave exactly as before.
 *
 * denied_at: set when a signed-in user refuses a pending redeemable session.
 * The status column is a strict ENUM and is deliberately left untouched: a
 * denied session is stored as status "revoked" plus denied_at.
 */
return new class extends Migration
{
    public function up()
    {
        Schema::table('golem15_user_device_auth_sessions', function (Blueprint $table) {
            $table->string('code_challenge', 64)->nullable()->after('short_code');
            $table->timestamp('denied_at')->nullable()->after('confirmed_at');
        });
    }

    public function down()
    {
        Schema::table('golem15_user_device_auth_sessions', function (Blueprint $table) {
            $table->dropColumn(['code_challenge', 'denied_at']);
        });
    }
};
