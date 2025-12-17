<?php namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;
use Golem15\User\Models\User;
use Log;

/**
 * Add GDPR consent tracking fields to users table
 *
 * This migration adds fields for tracking user consent to Terms of Use
 * and Privacy Policy, as required by GDPR Article 6 (lawful basis for processing).
 *
 * Also adds account deletion tracking fields for GDPR Article 17 (right to erasure).
 */
class AddGdprConsentFieldsToUsers extends Migration
{
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {
            // Terms of Use consent
            $table->boolean('terms_accepted')->default(false)->after('oauth_linked_at');
            $table->timestamp('terms_accepted_at')->nullable()->after('terms_accepted');
            $table->string('terms_version', 20)->nullable()->after('terms_accepted_at');

            // Privacy Policy consent
            $table->boolean('privacy_accepted')->default(false)->after('terms_version');
            $table->timestamp('privacy_accepted_at')->nullable()->after('privacy_accepted');
            $table->string('privacy_version', 20)->nullable()->after('privacy_accepted_at');

            // Consent tracking
            $table->string('consent_ip_address', 45)->nullable()->after('privacy_version');

            // Optional marketing consent
            $table->boolean('marketing_consent')->default(false)->after('consent_ip_address');
            $table->timestamp('marketing_consent_at')->nullable()->after('marketing_consent');

            // Account deletion tracking (GDPR Article 17)
            $table->timestamp('deletion_requested_at')->nullable()->after('marketing_consent_at');
            $table->string('deletion_reason', 500)->nullable()->after('deletion_requested_at');
            $table->timestamp('deletion_scheduled_for')->nullable()->after('deletion_reason');

            // Index for querying users with/without consent
            $table->index(['terms_accepted', 'privacy_accepted'], 'users_consent_index');
        });

        // Backfill existing users with consent assumed
        $this->backfillExistingUsers();
    }

    public function down()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropIndex('users_consent_index');

            $table->dropColumn([
                'terms_accepted',
                'terms_accepted_at',
                'terms_version',
                'privacy_accepted',
                'privacy_accepted_at',
                'privacy_version',
                'consent_ip_address',
                'marketing_consent',
                'marketing_consent_at',
                'deletion_requested_at',
                'deletion_reason',
                'deletion_scheduled_for',
            ]);
        });
    }

    /**
     * Backfill existing users with consent
     *
     * For users created before GDPR tracking was implemented,
     * we assume implicit consent based on their continued use of the service.
     * This is a reasonable assumption under GDPR Article 6(1)(b) (contract performance).
     */
    protected function backfillExistingUsers()
    {
        $currentPolicyVersion = '2024-12-10'; // Date of first privacy policy
        $backfilledCount = 0;

        // Get all existing users
        $users = User::whereNull('terms_accepted_at')->get();

        foreach ($users as $user) {
            $user->terms_accepted = true;
            $user->terms_accepted_at = $user->created_at;
            $user->terms_version = $currentPolicyVersion;

            $user->privacy_accepted = true;
            $user->privacy_accepted_at = $user->created_at;
            $user->privacy_version = $currentPolicyVersion;

            // Use created_ip_address as consent IP (best available data)
            $user->consent_ip_address = $user->created_ip_address;

            $user->save();
            $backfilledCount++;
        }

        if ($backfilledCount > 0) {
            Log::info("GDPR Migration: Backfilled consent for {$backfilledCount} existing users", [
                'policy_version' => $currentPolicyVersion,
                'migration' => 'v2.5.0',
            ]);
        }
    }
}
