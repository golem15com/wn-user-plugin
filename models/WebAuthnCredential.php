<?php

namespace Golem15\User\Models;

use Model;

/**
 * WebAuthnCredential Model
 *
 * Stores registered WebAuthn/FIDO2 public keys (YubiKeys, 1Password keys, etc.).
 *
 * @property int $id
 * @property int $user_id
 * @property string $credential_id
 * @property string $public_key
 * @property string|null $attestation_type
 * @property array|null $transports
 * @property int $sign_count
 * @property string|null $name
 * @property bool $is_enabled
 * @property \Carbon\Carbon|null $last_used_at
 * @property \Carbon\Carbon $created_at
 * @property \Carbon\Carbon $updated_at
 *
 * @property User $user
 */
class WebAuthnCredential extends Model
{
    public $table = 'golem15_user_webauthn_credentials';

    protected $guarded = ['*'];

    protected $fillable = [
        'user_id',
        'credential_id',
        'public_key',
        'attestation_type',
        'transports',
        'sign_count',
        'name',
        'is_enabled',
        'last_used_at',
    ];

    protected $dates = [
        'last_used_at',
        'created_at',
        'updated_at',
    ];

    protected $casts = [
        'is_enabled' => 'boolean',
        'transports' => 'array',
        'sign_count' => 'integer',
    ];

    public $belongsTo = [
        'user' => [User::class, 'key' => 'user_id'],
    ];

    /**
     * Touch the last_used_at timestamp and update sign count.
     */
    public function touchUsed(int $newSignCount): bool
    {
        $this->last_used_at = now();
        $this->sign_count = $newSignCount;
        return $this->save();
    }

    public function scopeEnabled($query)
    {
        return $query->where('is_enabled', true);
    }
}
