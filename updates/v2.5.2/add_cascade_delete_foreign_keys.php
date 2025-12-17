<?php namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;
use DB;
use Log;

/**
 * Add cascade delete to foreign keys for GDPR Article 17 compliance
 *
 * When a user is deleted (hard delete), all their related data must be automatically
 * removed to comply with GDPR "right to erasure" requirements.
 *
 * This migration updates existing foreign keys to add ON DELETE CASCADE behavior.
 */
class AddCascadeDeleteForeignKeys extends Migration
{
    public function up()
    {
        // 1. golem15_queststream_user_quests - player_id
        $this->updateForeignKey(
            'golem15_queststream_user_quests',
            'player_id',
            'users',
            'golem15_queststream_user_quests_player_id_foreign'
        );

        // 2. golem15_queststream_user_rewards - user_id
        $this->updateForeignKey(
            'golem15_queststream_user_rewards',
            'user_id',
            'users',
            'golem15_queststream_user_rewards_user_id_foreign'
        );

        // 3. golem15_queststream_user_achievements - user_id
        $this->updateForeignKey(
            'golem15_queststream_user_achievements',
            'user_id',
            'users',
            'golem15_queststream_user_achievements_user_id_foreign'
        );

        // 4. golem15_queststream_family_invitations - invited_user_id (CASCADE) and invited_by (SET NULL)
        $this->updateForeignKey(
            'golem15_queststream_family_invitations',
            'invited_user_id',
            'users',
            'golem15_queststream_family_invitations_invited_user_id_foreign',
            'cascade'
        );

        // invited_by should SET NULL (keep invitation record but remove inviter reference)
        $this->updateForeignKey(
            'golem15_queststream_family_invitations',
            'invited_by',
            'users',
            'golem15_queststream_family_invitations_invited_by_foreign',
            'set null'
        );

        Log::info("GDPR Migration: Added cascade delete to foreign keys", [
            'migration' => 'v2.5.2',
            'tables_updated' => [
                'golem15_queststream_user_quests',
                'golem15_queststream_user_rewards',
                'golem15_queststream_user_achievements',
                'golem15_queststream_family_invitations',
            ],
        ]);
    }

    public function down()
    {
        // Restore original foreign keys without cascade
        $this->restoreForeignKey(
            'golem15_queststream_user_quests',
            'player_id',
            'users',
            'golem15_queststream_user_quests_player_id_foreign',
            'restrict'
        );

        $this->restoreForeignKey(
            'golem15_queststream_user_rewards',
            'user_id',
            'users',
            'golem15_queststream_user_rewards_user_id_foreign',
            'restrict'
        );

        $this->restoreForeignKey(
            'golem15_queststream_user_achievements',
            'user_id',
            'users',
            'golem15_queststream_user_achievements_user_id_foreign',
            'restrict'
        );

        $this->restoreForeignKey(
            'golem15_queststream_family_invitations',
            'invited_user_id',
            'users',
            'golem15_queststream_family_invitations_invited_user_id_foreign',
            'restrict'
        );

        $this->restoreForeignKey(
            'golem15_queststream_family_invitations',
            'invited_by',
            'users',
            'golem15_queststream_family_invitations_invited_by_foreign',
            'restrict'
        );
    }

    /**
     * Update foreign key to add cascade delete
     *
     * @param string $table Table name
     * @param string $column Foreign key column
     * @param string $references Referenced table
     * @param string $constraintName Existing constraint name
     * @param string $onDelete Delete action (default: cascade)
     */
    protected function updateForeignKey($table, $column, $references, $constraintName, $onDelete = 'cascade')
    {
        // Check if table exists
        if (!Schema::hasTable($table)) {
            Log::warning("GDPR Migration: Table {$table} does not exist, skipping foreign key update");
            return;
        }

        // Check if column exists
        if (!Schema::hasColumn($table, $column)) {
            Log::warning("GDPR Migration: Column {$column} does not exist in table {$table}, skipping");
            return;
        }

        // Check if foreign key exists using database query
        $database = DB::getDatabaseName();
        $foreignKeyExists = DB::select(
            "SELECT CONSTRAINT_NAME
             FROM information_schema.TABLE_CONSTRAINTS
             WHERE TABLE_SCHEMA = ?
             AND TABLE_NAME = ?
             AND CONSTRAINT_TYPE = 'FOREIGN KEY'
             AND CONSTRAINT_NAME LIKE ?",
            [$database, $table, "%{$column}%"]
        );

        // Drop existing foreign key if it exists
        if (!empty($foreignKeyExists)) {
            $actualConstraintName = $foreignKeyExists[0]->CONSTRAINT_NAME;
            DB::statement("ALTER TABLE {$table} DROP FOREIGN KEY {$actualConstraintName}");
            Log::info("GDPR Migration: Dropped existing foreign key {$actualConstraintName}");
        }

        // Add foreign key with cascade/set null
        Schema::table($table, function (Blueprint $table) use ($column, $references, $onDelete) {
            $table->foreign($column)
                  ->references('id')
                  ->on($references)
                  ->onDelete($onDelete);
        });

        Log::info("GDPR Migration: Updated foreign key", [
            'table' => $table,
            'column' => $column,
            'on_delete' => $onDelete,
        ]);
    }

    /**
     * Restore foreign key without cascade (for rollback)
     */
    protected function restoreForeignKey($table, $column, $references, $constraintName, $onDelete = 'restrict')
    {
        if (!Schema::hasTable($table)) {
            return;
        }

        Schema::table($table, function (Blueprint $table) use ($column, $references, $onDelete) {
            try {
                $table->dropForeign([$column]);
            } catch (\Exception $e) {
                // Ignore if foreign key doesn't exist
            }

            $table->foreign($column)
                  ->references('id')
                  ->on($references)
                  ->onDelete($onDelete);
        });
    }
}
