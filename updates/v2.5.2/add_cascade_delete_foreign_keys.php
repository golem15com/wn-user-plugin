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
        // Generic, table-agnostic GDPR cascade-FK hook. Plugins that own related
        // tables register a listener on 'golem15.user.gdprCascadeForeignKeys' and
        // push their target columns. With no listeners registered this is a
        // silent no-op (the plugins that own those tables declare cascade FKs
        // in their own migrations).
        $updated = [];
        foreach ($this->cascadeTargets() as $t) {
            if ($this->updateForeignKey(
                $t['table'],
                $t['column'],
                $t['references'] ?? 'users',
                $t['constraint'] ?? null,
                $t['on_delete'] ?? 'cascade'
            )) {
                $updated[] = $t['table'] . '.' . $t['column'];
            }
        }

        // Only log a summary when this migration actually touched something.
        if (!empty($updated)) {
            Log::info("GDPR Migration: Added cascade delete to foreign keys", [
                'migration' => 'v2.5.2',
                'tables_updated' => $updated,
            ]);
        }
    }

    public function down()
    {
        foreach ($this->cascadeTargets() as $t) {
            $this->restoreForeignKey(
                $t['table'],
                $t['column'],
                $t['references'] ?? 'users',
                $t['constraint'] ?? null,
                'restrict'
            );
        }
    }

    /**
     * Collect cascade-FK targets from plugins. Each listener returns a list of
     * entries of the form
     * ['table' => ..., 'column' => ..., 'on_delete' => 'cascade'|'set null'].
     *
     * Entries are plugin-controlled, so malformed ones (not an array, or missing
     * the required 'table'/'column' keys) are skipped rather than allowed to
     * raise undefined-key warnings or break the migration.
     *
     * @return array
     */
    protected function cascadeTargets(): array
    {
        $results = (array) \Event::fire('golem15.user.gdprCascadeForeignKeys', [], false);

        $targets = [];
        foreach ($results as $set) {
            if (!is_array($set)) {
                continue;
            }
            foreach ($set as $entry) {
                if (is_array($entry) && !empty($entry['table']) && !empty($entry['column'])) {
                    $targets[] = $entry;
                } else {
                    Log::debug('GDPR Migration: skipping malformed cascade-FK target', [
                        'entry' => $entry,
                    ]);
                }
            }
        }

        return $targets;
    }

    /**
     * Update foreign key to add cascade delete
     *
     * @param string $table Table name
     * @param string $column Foreign key column
     * @param string $references Referenced table
     * @param string $constraintName Existing constraint name
     * @param string $onDelete Delete action (default: cascade)
     * @return bool True if the foreign key was updated, false if the table/column was absent (no-op)
     */
    protected function updateForeignKey($table, $column, $references, $constraintName, $onDelete = 'cascade')
    {
        // Absent table/column is an expected no-op in projects that don't ship the
        // target tables. Use debug level so it never floods info/warning logs.
        if (!Schema::hasTable($table)) {
            Log::debug("GDPR Migration: Table {$table} does not exist, skipping foreign key update");
            return false;
        }

        if (!Schema::hasColumn($table, $column)) {
            Log::debug("GDPR Migration: Column {$column} does not exist in table {$table}, skipping");
            return false;
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

        return true;
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
