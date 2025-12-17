<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Current Policy Versions
    |--------------------------------------------------------------------------
    |
    | These version numbers are recorded when users accept terms/privacy.
    | Update these when you release new policy versions.
    |
    | Format: YYYY-MM-DD (matches policy last updated date)
    |
    */

    'current_terms_version' => '2024-12-17',
    'current_privacy_version' => '2024-12-17',

    /*
    |--------------------------------------------------------------------------
    | Account Deletion Grace Period
    |--------------------------------------------------------------------------
    |
    | Number of days users have to cancel deletion before permanent removal.
    | GDPR requires reasonable time for users to change their mind.
    |
    */

    'deletion_grace_period_days' => 30,

    /*
    |--------------------------------------------------------------------------
    | Data Export Settings
    |--------------------------------------------------------------------------
    |
    | Configuration for GDPR data export (Articles 15 & 20)
    |
    */

    'export_format' => 'json', // Options: json, csv (future)
    'export_version' => '1.0',
    'export_filename_pattern' => 'queststream-data-export-{user_id}-{date}.json',

    /*
    |--------------------------------------------------------------------------
    | Consent Audit Settings
    |--------------------------------------------------------------------------
    |
    | Controls for consent audit trail logging
    |
    */

    'audit_consent_changes' => true,
    'audit_retention_years' => 7, // Keep audit records for 7 years (compliance requirement)

    /*
    |--------------------------------------------------------------------------
    | Privacy Policy Settings
    |--------------------------------------------------------------------------
    |
    | URLs and metadata for privacy-related pages
    |
    */

    'privacy_policy_url' => '/privacy',
    'terms_of_use_url' => '/terms',
    'privacy_kids_url' => '/privacy-kids',
    'privacy_changelog_url' => '/privacy-changelog',

    /*
    |--------------------------------------------------------------------------
    | Data Controller Information
    |--------------------------------------------------------------------------
    |
    | Organization details for GDPR compliance (Article 13)
    |
    */

    'data_controller' => [
        'name' => 'Golem15 Sp. z o.o.',
        'address' => 'ul. Rzeźnicza 32a, 63-460 Namysłów, Poland',
        'email' => 'privacy@golem15.com',
        'dpo_email' => 'dpo@golem15.com', // Data Protection Officer
    ],

    /*
    |--------------------------------------------------------------------------
    | GDPR Features Toggle
    |--------------------------------------------------------------------------
    |
    | Enable/disable GDPR features (useful for testing or staged rollout)
    |
    */

    'features' => [
        'consent_tracking' => true,
        'data_export' => true,
        'account_deletion' => true,
        'consent_audit' => true,
    ],

];
