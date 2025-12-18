<?php namespace Golem15\User\Updates;

use Winter\Storm\Database\Updates\Migration;
use Golem15\User\Models\User;
use Log;

/**
 * Backfill cookie consent for existing users
 *
 * For users who already accepted the Privacy Policy (which mentions cookies),
 * we assume implicit consent for cookie usage. This is reasonable under GDPR
 * Article 6(1)(b) (contract performance) since:
 * 1. Privacy Policy Section 11 already disclosed cookie usage
 * 2. Only essential cookies are currently used
 * 3. Users explicitly accepted Privacy Policy with cookie disclosure
 */
class BackfillCookieConsent extends Migration
{
    public function up()
    {
        $currentVersion = '2024-12-17';
        $backfilledCount = 0;

        // Get users who have privacy consent but no cookie consent
        $users = User::whereNotNull('privacy_accepted_at')
            ->whereNull('cookie_consent_at')
            ->get();

        foreach ($users as $user) {
            // Essential only (current state of the platform)
            $user->cookie_preferences = [
                'essential' => true,
                'analytics' => false,
                'marketing' => false,
                'accepted_at' => $user->privacy_accepted_at->toIso8601String(),
                'version' => $currentVersion,
            ];

            // Use privacy consent timestamp as cookie consent timestamp
            $user->cookie_consent_at = $user->privacy_accepted_at;
            $user->cookie_consent_version = $currentVersion;
            $user->save();

            $backfilledCount++;
        }

        if ($backfilledCount > 0) {
            Log::info("Cookie Consent Backfill: {$backfilledCount} users", [
                'version' => $currentVersion,
                'migration' => 'v2.6.0',
                'assumptions' => 'Implicit consent via privacy policy acceptance',
            ]);
        }
    }

    public function down()
    {
        // No rollback needed - backfill is non-destructive
    }
}
