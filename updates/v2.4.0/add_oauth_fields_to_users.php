<?php namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Updates\Migration;

/**
 * Add OAuth fields to users table for social login support (Google, Facebook, etc.)
 */
class AddOAuthFieldsToUsers extends Migration
{
    public function up()
    {
        Schema::table('users', function ($table) {
            // OAuth provider name (google, facebook, github, etc.)
            $table->string('oauth_provider', 50)->nullable()->index();

            // Unique user ID from the OAuth provider
            $table->string('oauth_provider_id', 255)->nullable()->index();

            // Access token (encrypted for security)
            $table->text('oauth_access_token')->nullable();

            // Refresh token (encrypted for security)
            $table->text('oauth_refresh_token')->nullable();

            // Token expiration timestamp
            $table->timestamp('oauth_token_expires_at')->nullable();

            // Additional profile data from provider (name, avatar, etc.)
            $table->json('oauth_profile_data')->nullable();

            // When the OAuth account was linked
            $table->timestamp('oauth_linked_at')->nullable();

            // Ensure unique provider + provider_id combination
            // Prevents same Google account linked to multiple QuestStream users
            $table->unique(['oauth_provider', 'oauth_provider_id'], 'oauth_unique_provider_user');
        });
    }

    public function down()
    {
        Schema::table('users', function ($table) {
            // Drop unique constraint first
            $table->dropUnique('oauth_unique_provider_user');

            // Drop OAuth columns
            $table->dropColumn([
                'oauth_provider',
                'oauth_provider_id',
                'oauth_access_token',
                'oauth_refresh_token',
                'oauth_token_expires_at',
                'oauth_profile_data',
                'oauth_linked_at'
            ]);
        });
    }
}
