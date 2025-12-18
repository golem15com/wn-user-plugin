<?php namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;

/**
 * Add Parental Authority Fields to Users Table
 *
 * Tracks explicit parental authority declaration required for GDPR Article 8 compliance.
 * Polish law (RODO) requires parental consent for children under 16 years old.
 *
 * Fields:
 * - parental_authority_confirmed: Boolean flag indicating declaration was accepted
 * - parental_authority_confirmed_at: Timestamp when declaration was confirmed
 *
 * @package Golem15\User
 * @author Jakub Zych
 */
class AddParentalAuthorityToUsers extends Migration
{
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {
            // Parental authority declaration confirmed (required for parent accounts)
            $table->boolean('parental_authority_confirmed')->default(false)->after('marketing_consent_at');

            // Timestamp when parental authority was confirmed
            $table->timestamp('parental_authority_confirmed_at')->nullable()->after('parental_authority_confirmed');
        });
    }

    public function down()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn(['parental_authority_confirmed', 'parental_authority_confirmed_at']);
        });
    }
}
