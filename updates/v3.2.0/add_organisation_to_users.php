<?php

namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;

/**
 * Phase 12 (WS-1): Additive org relation on the shared `users` table.
 *
 * STRICTLY ADDITIVE (core-plugin no-breaking rule): two nullable columns plus a
 * FK to golem15_user_organisations. Existing columns are never touched. The FK
 * uses onDelete('set null') so deleting an Organisation never orphans/cascades a
 * delete onto its members (T-12-fk-integrity) — the user simply loses their org
 * link. The FK/index name is explicit and < 64 chars (MySQL identifier limit).
 *
 * This migration MUST run AFTER create_organisations_table (it references it).
 */
class AddOrganisationToUsers extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->unsignedInteger('organisation_id')->nullable();
            $table->string('organisation_role')->nullable();
            $table->foreign('organisation_id', 'g15_user_org_fk')
                  ->references('id')->on('golem15_user_organisations')
                  ->onDelete('set null');
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropForeign('g15_user_org_fk');
            $table->dropColumn(['organisation_id', 'organisation_role']);
        });
    }
}
