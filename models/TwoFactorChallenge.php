<?php

namespace Golem15\User\Models;

use Carbon\Carbon;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Model;

/**
 * TwoFactorChallenge Model
 *
 * Short-lived challenge sessions between password verification and 2FA completion.
 * Follows the DeviceAuthSession pattern.
 *
 * @property int $id
 * @property int $user_id
 * @property string $token
 * @property string|null $method
 * @property string|null $code
 * @property int $attempts
 * @property int $max_attempts
 * @property string|null $ip_address
 * @property string|null $user_agent
 * @property \Carbon\Carbon $expires_at
 * @property \Carbon\Carbon|null $completed_at
 * @property \Carbon\Carbon $created_at
 * @property \Carbon\Carbon $updated_at
 *
 * @property User $user
 */
class TwoFactorChallenge extends Model
{
    public $table = 'golem15_user_two_factor_challenges';

    protected $guarded = ['*'];

    protected $fillable = [
        'user_id',
        'token',
        'method',
        'code',
        'attempts',
        'max_attempts',
        'ip_address',
        'user_agent',
        'expires_at',
        'completed_at',
    ];

    protected $dates = [
        'expires_at',
        'completed_at',
        'created_at',
        'updated_at',
    ];

    protected $casts = [
        'attempts' => 'integer',
        'max_attempts' => 'integer',
    ];

    public $belongsTo = [
        'user' => [User::class, 'key' => 'user_id'],
    ];

    /**
     * Generate a new 2FA challenge for a user.
     *
     * @param User $user
     * @param string|null $ipAddress
     * @param string|null $userAgent
     * @param int $expiryMinutes
     * @return static
     */
    public static function generate(User $user, ?string $ipAddress = null, ?string $userAgent = null, int $expiryMinutes = 5): self
    {
        // Clean up expired challenges for this user
        self::cleanupExpired($user->id);

        return self::create([
            'user_id' => $user->id,
            'token' => self::generateUniqueToken(),
            'ip_address' => $ipAddress ?? request()->ip(),
            'user_agent' => $userAgent ?? request()->userAgent(),
            'expires_at' => Carbon::now()->addMinutes($expiryMinutes),
        ]);
    }

    /**
     * Generate a unique 64-character token.
     */
    protected static function generateUniqueToken(): string
    {
        do {
            $token = Str::random(64);
        } while (self::where('token', $token)->exists());

        return $token;
    }

    /**
     * Find a valid (non-expired, non-completed, non-exhausted) challenge by token.
     */
    public static function findValidToken(string $token): ?self
    {
        $challenge = self::where('token', $token)->first();

        if (!$challenge) {
            return null;
        }

        if ($challenge->isExpired() || $challenge->isCompleted() || $challenge->isExhausted()) {
            return null;
        }

        return $challenge;
    }

    public function isExpired(): bool
    {
        return Carbon::now()->greaterThan($this->expires_at);
    }

    public function isCompleted(): bool
    {
        return $this->completed_at !== null;
    }

    public function isExhausted(): bool
    {
        return $this->attempts >= $this->max_attempts;
    }

    public function incrementAttempts(): bool
    {
        $this->attempts++;
        return $this->save();
    }

    public function markCompleted(): bool
    {
        $this->completed_at = Carbon::now();
        return $this->save();
    }

    /**
     * Store a hashed email verification code on this challenge.
     */
    public function setEmailCode(string $plainCode): bool
    {
        $this->method = TwoFactorMethod::METHOD_EMAIL;
        $this->code = Hash::make($plainCode);
        return $this->save();
    }

    /**
     * Verify an email code against the stored hash.
     */
    public function verifyEmailCode(string $plainCode): bool
    {
        if (!$this->code) {
            return false;
        }

        return Hash::check($plainCode, $this->code);
    }

    /**
     * Clean up expired challenges for a user.
     */
    public static function cleanupExpired(?int $userId = null): int
    {
        $query = self::where('expires_at', '<', Carbon::now())
            ->whereNull('completed_at');

        if ($userId) {
            $query->where('user_id', $userId);
        }

        return $query->delete();
    }

    public function scopePending($query)
    {
        return $query->whereNull('completed_at')
            ->where('expires_at', '>', Carbon::now());
    }
}
