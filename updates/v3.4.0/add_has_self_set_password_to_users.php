<?php

namespace Golem15\User\Updates\v3_4_0;

use DB;
use Schema;
use Winter\Storm\Database\Updates\Migration;

/**
 * Additive: a boolean "has_self_set_password" flag on users, defaulting to `true`.
 *
 * Closes k7ut351s: an account created via OAuth registration never had a chance to
 * set its own password — `SocialAuth.php` fills `password` with `Str::random(16)` at
 * registration time, so `Hash::check()` in the change-password flow can never pass.
 * This flag lets the change-password / CMS Account::onUpdate paths skip the
 * "current password" requirement for exactly this cohort, and nothing else.
 *
 * Default `true` is deliberate and non-negotiable: every existing row and every
 * future self-registered account is unaffected and keeps the "current password
 * required" behaviour unchanged (non-breaking, core plugin, CLAUDE.md §core plugins).
 *
 * Backfill: immediately after adding the column, every user with a row in
 * `golem15_user_oauth_identities` is flipped to `false`, because that is the only
 * signal in the schema that a user's `password` column might hold the
 * `Str::random(16)` placeholder rather than a real, user-chosen secret. Idempotent —
 * running `up()` again only ever re-sets rows to the same `false` they already have.
 *
 * Known, accepted cost of this backfill (see 14-01-PLAN.md T-14-08): an OAuth-linked
 * account that had ALREADY set a real password of its own (e.g. via the existing
 * `/forgot-password` flow, which requires no current password either) will also be
 * flipped to `false` by this backfill. The schema has no column that distinguishes
 * "real self-chosen password" from "random placeholder" for an OAuth-linked account,
 * so there is no way to backfill more precisely. The window this opens is one-time
 * per account: the very first successful password write (change-password,
 * reset-password, or CMS onUpdate) flips the flag back to `true` (see Task 2). It
 * only applies to accounts with a live, verified OAuth link and requires an active,
 * authenticated session — it does not open any attack class that the pre-existing,
 * undocumented `/forgot-password` bypass did not already open.
 */
class AddHasSelfSetPasswordToUsers extends Migration
{
    public function up()
    {
        if (!Schema::hasColumn('users', 'has_self_set_password')) {
            Schema::table('users', function ($table) {
                $table->boolean('has_self_set_password')->default(true);
            });
        }

        if (Schema::hasTable('golem15_user_oauth_identities')) {
            DB::table('users')
                ->whereIn('id', function ($query) {
                    $query->select('user_id')->from('golem15_user_oauth_identities');
                })
                ->update(['has_self_set_password' => false]);
        }
    }

    public function down()
    {
        if (Schema::hasColumn('users', 'has_self_set_password')) {
            Schema::table('users', function ($table) {
                $table->dropColumn('has_self_set_password');
            });
        }
    }
}
