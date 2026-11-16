<?php

namespace Golem15\User\Updates\v3_5_0;

use Schema;
use Winter\Storm\Database\Updates\Migration;

/**
 * Additive: a nullable "last_totp_timestep" column on golem15_user_two_factor_methods.
 *
 * TOTP replay guard (phase 106.1, D-28). It stores the 30-second timestep of the last
 * TOTP code accepted for the row, so the same code cannot be accepted twice inside its
 * validity window. TotpMethod::verify() claims a newer timestep with one conditional
 * UPDATE (`last_totp_timestep IS NULL OR last_totp_timestep < :ts`), so two concurrent
 * requests carrying the same code cannot both pass.
 *
 * Nullable with no default: every existing row starts at NULL, which means "no code
 * accepted yet", so nothing changes for existing users until their next sign-in.
 * Non-TOTP rows (email, webauthn) never write it.
 */
class AddLastTotpTimestepToTwoFactorMethods extends Migration
{
    public function up()
    {
        if (!Schema::hasColumn('golem15_user_two_factor_methods', 'last_totp_timestep')) {
            Schema::table('golem15_user_two_factor_methods', function ($table) {
                $table->unsignedBigInteger('last_totp_timestep')->nullable()->after('secret');
            });
        }
    }

    public function down()
    {
        if (Schema::hasColumn('golem15_user_two_factor_methods', 'last_totp_timestep')) {
            Schema::table('golem15_user_two_factor_methods', function ($table) {
                $table->dropColumn('last_totp_timestep');
            });
        }
    }
}
