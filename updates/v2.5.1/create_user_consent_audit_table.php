<?php namespace Golem15\User\Updates;

use Schema;
use Winter\Storm\Database\Schema\Blueprint;
use Winter\Storm\Database\Updates\Migration;

/**
 * Create consent audit table for GDPR compliance
 *
 * This table tracks all consent-related actions (granted, withdrawn, updated)
 * providing a complete audit trail for regulatory compliance and user transparency.
 *
 * Required by GDPR Article 7(1): "The controller shall be able to demonstrate
 * that the data subject has consented to processing of his or her personal data."
 */
class CreateUserConsentAuditTable extends Migration
{
    public function up()
    {
        Schema::create('golem15_user_consent_audit', function (Blueprint $table) {
            $table->increments('id');

            // User reference (cascade delete when user is deleted)
            $table->integer('user_id')->unsigned();

            // Type of consent
            $table->enum('consent_type', ['terms', 'privacy', 'marketing'])
                  ->comment('Type of consent: terms (Terms of Use), privacy (Privacy Policy), marketing (Marketing emails)');

            // Action performed
            $table->enum('action', ['granted', 'withdrawn', 'updated'])
                  ->comment('Action: granted (new consent), withdrawn (consent removed), updated (policy version changed)');

            // Policy version (for terms and privacy)
            $table->string('policy_version', 20)->nullable()
                  ->comment('Version of policy accepted (e.g., "2024-12-17")');

            // Tracking information
            $table->string('ip_address', 45)->nullable()
                  ->comment('IP address at time of consent action');

            $table->text('user_agent')->nullable()
                  ->comment('Browser user agent string');

            // Optional metadata (JSON)
            $table->json('metadata')->nullable()
                  ->comment('Additional context (e.g., OAuth provider for social login)');

            // Timestamps
            $table->timestamps();

            // Foreign key with cascade delete
            $table->foreign('user_id')
                  ->references('id')
                  ->on('users')
                  ->onDelete('cascade');

            // Indexes for efficient queries
            $table->index(['user_id', 'consent_type', 'created_at'], 'consent_audit_lookup');
            $table->index('created_at', 'consent_audit_date');
        });
    }

    public function down()
    {
        Schema::dropIfExists('golem15_user_consent_audit');
    }
}
