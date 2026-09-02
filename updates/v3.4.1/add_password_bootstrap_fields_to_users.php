<?php

namespace Golem15\User\Updates\v3_4_1;

use Schema;
use Winter\Storm\Database\Updates\Migration;

/**
 * Additive: three new nullable/defaulted columns closing CR-01 and half of T-14-08
 * (code review of Phase 14, plan 01, ticket k7ut351s).
 *
 * CR-01 (critical): `has_self_set_password === false` alone used to be sufficient for
 * ApiController::changePassword() / Account::onUpdate() to skip `current_password`
 * entirely -- a stolen bearer JWT was then enough to permanently overwrite the
 * account's password. `password_bootstrap_code` + `password_bootstrap_code_expires_at`
 * back a short-lived, single-use confirmation code emailed to the account's own
 * registered address before that relaxed write is allowed to commit: proof of mailbox
 * access, a capability a stolen bearer token alone does not grant (see 14-REVIEW.md).
 * The code itself is stored hashed (`Hash::make`), never in plaintext, the same way
 * `password` is.
 *
 * T-14-08 (accepted-risk refinement): `password_bootstrap_source` distinguishes the
 * two populations the review flagged as needing different treatment --
 *  - 'oauth_registration': set at OAuth registration time (SocialAuth.php), a VERIFIED
 *    placeholder password (Str::random(16)) that the account genuinely never chose.
 *  - null: everyone else, including every account the v3.4.0 migration backfill
 *    flagged `has_self_set_password = false` -- the backfill has no way to tell a
 *    genuine placeholder apart from a real, user-chosen password on an OAuth-linked
 *    account, so this population stays UNVERIFIED. Both populations are held to the
 *    same CR-01 confirmation-code requirement today (the review's attack chain does
 *    not distinguish them), but the marker makes the two auditable and leaves room to
 *    tighten policy for the unverified cohort later without another migration.
 *
 * All three columns are nullable and untouched by default -- every existing row and
 * every project that never triggers the relaxed path is completely unaffected
 * (non-breaking, core plugin, CLAUDE.md "core plugins ... cannot have breaking
 * changes").
 */
class AddPasswordBootstrapFieldsToUsers extends Migration
{
    public function up()
    {
        Schema::table('users', function ($table) {
            if (!Schema::hasColumn('users', 'password_bootstrap_source')) {
                $table->string('password_bootstrap_source', 32)->nullable()->default(null);
            }
            if (!Schema::hasColumn('users', 'password_bootstrap_code')) {
                $table->string('password_bootstrap_code')->nullable()->default(null);
            }
            if (!Schema::hasColumn('users', 'password_bootstrap_code_expires_at')) {
                $table->timestamp('password_bootstrap_code_expires_at')->nullable()->default(null);
            }
        });
    }

    public function down()
    {
        // Deliberately three separate Schema::table() calls, not one Blueprint with
        // three dropColumn()s: SQLite has no native DROP COLUMN and Laravel emulates it
        // by rebuilding the table from a column listing snapshot. Batching multiple
        // drops into a single Blueprint produced an inconsistent rebuild in manual
        // testing against a real (non-memory) SQLite file -- the temp-table SELECT
        // referenced a column from an earlier drop that should already have been gone.
        // One drop per Schema::table() call avoids that entirely and is proven safe by
        // manual up()/down()/up() round-trip testing on a real SQLite file, not just
        // Schema::hasColumn() guard-presence inspection.
        if (Schema::hasColumn('users', 'password_bootstrap_code_expires_at')) {
            Schema::table('users', function ($table) {
                $table->dropColumn('password_bootstrap_code_expires_at');
            });
        }
        if (Schema::hasColumn('users', 'password_bootstrap_code')) {
            Schema::table('users', function ($table) {
                $table->dropColumn('password_bootstrap_code');
            });
        }
        if (Schema::hasColumn('users', 'password_bootstrap_source')) {
            Schema::table('users', function ($table) {
                $table->dropColumn('password_bootstrap_source');
            });
        }
    }
}
