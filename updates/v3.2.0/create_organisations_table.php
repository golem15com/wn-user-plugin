<?php

namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;

/**
 * Phase 12 (WS-1): Organisations for multi-user self-hostable deployments.
 *
 * Structure only — no logic. An Organisation groups members (users) under a
 * shared identity (slug, name, description) plus a polymorphic avatar
 * (attachOne to system_files, so no avatar column is needed here). The
 * golem15_* table prefix follows the core-plugin naming convention. This
 * migration MUST run BEFORE add_organisation_to_users (whose FK references it).
 */
class CreateOrganisationsTable extends Migration
{
    public function up(): void
    {
        Schema::create('golem15_user_organisations', function (Blueprint $table) {
            $table->increments('id');
            $table->string('slug')->unique();
            $table->string('name');
            $table->text('description')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('golem15_user_organisations');
    }
}
