<?php

namespace Golem15\User\Models;

use Carbon\Carbon;
use Model;

/**
 * A single linked OAuth provider identity for a user. A user may have at most one row per
 * provider (unique on user_id+provider) and a provider identity may belong to at most one
 * user (unique on provider+provider_id) — see the golem15_user_oauth_identities migration.
 *
 * Deliberately $guarded=['*'] with NO $fillable array at all — provider/provider_id/tokens must
 * never be mass-assignable (see plugins/golem15/user/tests/security/DataHandlingTest.php);
 * every write happens via explicit property assignment inside User::linkOAuthProvider().
 */
class OAuthIdentity extends Model
{
    public $table = 'golem15_user_oauth_identities';

    protected $guarded = ['*'];

    protected $dates = [
        'token_expires_at',
        'linked_at',
        'created_at',
        'updated_at',
    ];

    protected $casts = [
        'profile_data' => 'array',
    ];

    public $belongsTo = [
        'user' => [User::class, 'key' => 'user_id'],
    ];

    public function setAccessToken(?string $token): void
    {
        $this->access_token = $token ? encrypt($token) : null;
    }

    public function setRefreshToken(?string $token): void
    {
        $this->refresh_token = $token ? encrypt($token) : null;
    }

    public function getAccessToken(): ?string
    {
        if (!$this->access_token) {
            return null;
        }

        try {
            return decrypt($this->access_token);
        } catch (\Exception $e) {
            \Log::error('Failed to decrypt OAuth access token', [
                'user_id' => $this->user_id,
                'provider' => $this->provider,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    public function getRefreshToken(): ?string
    {
        if (!$this->refresh_token) {
            return null;
        }

        try {
            return decrypt($this->refresh_token);
        } catch (\Exception $e) {
            \Log::error('Failed to decrypt OAuth refresh token', [
                'user_id' => $this->user_id,
                'provider' => $this->provider,
                'error' => $e->getMessage()
            ]);
            return null;
        }
    }

    public function isExpired(): bool
    {
        if (!$this->token_expires_at) {
            return false;
        }

        return Carbon::now()->isAfter($this->token_expires_at);
    }

    public function getDisplayName(): string
    {
        $providers = [
            'google' => 'Google',
            'facebook' => 'Facebook',
            'github' => 'GitHub',
        ];

        return $providers[$this->provider] ?? ucfirst($this->provider);
    }
}
