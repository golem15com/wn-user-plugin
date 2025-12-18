<?php namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;

/**
 * Add cookie consent tracking fields to users table
 *
 * This migration adds fields for tracking user cookie consent preferences
 * as required by GDPR Article 6 and ePrivacy Directive.
 *
 * Supports future-proof cookie categories (essential, analytics, marketing)
 * even though currently only essential cookies are used.
 */
class AddCookieConsentToUsers extends Migration
{
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {
            // Cookie consent preferences (JSON for flexibility)
            $table->json('cookie_preferences')->nullable()->after('consent_ip_address');

            // Cookie consent tracking
            $table->timestamp('cookie_consent_at')->nullable()->after('cookie_preferences');
            $table->string('cookie_consent_version', 20)->nullable()->after('cookie_consent_at');
        });
    }

    public function down()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn([
                'cookie_preferences',
                'cookie_consent_at',
                'cookie_consent_version',
            ]);
        });
    }
}
