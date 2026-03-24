<?php

namespace Golem15\User\Models;

use Model;

/**
 * TwoFactorMethod Model
 *
 * Tracks which 2FA methods a user has enabled (TOTP, WebAuthn, Email).
 *
 * @property int $id
 * @property int $user_id
 * @property string $method
 * @property bool $is_enabled
 * @property string|null $secret
 * @property array|null $metadata
 * @property \Carbon\Carbon|null $last_used_at
 * @property \Carbon\Carbon $created_at
 * @property \Carbon\Carbon $updated_at
 *
 * @property User $user
 */
class TwoFactorMethod extends Model
{
    public $table = 'golem15_user_two_factor_methods';

    protected $guarded = ['*'];

    protected $fillable = [
        'user_id',
        'method',
        'is_enabled',
        'secret',
        'metadata',
        'last_used_at',
    ];

    protected $dates = [
        'last_used_at',
        'created_at',
        'updated_at',
    ];

    protected $casts = [
        'is_enabled' => 'boolean',
        'metadata' => 'array',
    ];

    public $belongsTo = [
        'user' => [User::class, 'key' => 'user_id'],
    ];

    const METHOD_TOTP = 'totp';
    const METHOD_WEBAUTHN = 'webauthn';
    const METHOD_EMAIL = 'email';

    /**
     * Encrypt the secret before saving.
     */
    public function setSecretAttribute($value)
    {
        $this->attributes['secret'] = $value ? encrypt($value) : null;
    }

    /**
     * Decrypt the secret when reading.
     */
    public function getSecretAttribute($value)
    {
        if (!$value) {
            return null;
        }

        try {
            return decrypt($value);
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Touch the last_used_at timestamp.
     */
    public function touchLastUsed(): bool
    {
        $this->last_used_at = now();
        return $this->save();
    }

    public function scopeEnabled($query)
    {
        return $query->where('is_enabled', true);
    }

    public function scopeForMethod($query, string $method)
    {
        return $query->where('method', $method);
    }
}
