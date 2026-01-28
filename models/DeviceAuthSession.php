<?php

namespace Golem15\User\Models;

use Carbon\Carbon;
use Illuminate\Support\Str;
use Model;

/**
 * DeviceAuthSession Model
 *
 * Manages QR code-based device authorization sessions.
 * Allows parents to authorize new devices by scanning a QR code.
 *
 * @property int $id
 * @property string $token
 * @property int $user_id
 * @property string $status
 * @property Carbon $expires_at
 * @property string|null $device_ip
 * @property string|null $device_user_agent
 * @property string|null $device_name
 * @property string|null $auth_ip
 * @property Carbon|null $confirmed_at
 * @property Carbon|null $used_at
 * @property string|null $session_id
 * @property Carbon|null $last_activity_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 *
 * @property User $user
 */
class DeviceAuthSession extends Model
{
    /**
     * @var string The database table used by the model.
     */
    public $table = 'golem15_user_device_auth_sessions';

    /**
     * @var array Guarded fields
     */
    protected $guarded = ['*'];

    /**
     * @var array Fillable fields
     */
    protected $fillable = [
        'token',
        'short_code',
        'user_id',
        'status',
        'expires_at',
        'device_ip',
        'device_user_agent',
        'device_name',
        'auth_ip',
        'confirmed_at',
        'used_at',
        'session_id',
        'last_activity_at',
    ];

    /**
     * @var array Date fields
     */
    protected $dates = [
        'expires_at',
        'confirmed_at',
        'used_at',
        'last_activity_at',
        'created_at',
        'updated_at',
    ];

    /**
     * @var array Relations
     */
    public $belongsTo = [
        'user' => [User::class, 'key' => 'user_id'],
    ];

    /**
     * Status constants
     */
    const STATUS_PENDING = 'pending';
    const STATUS_CONFIRMED = 'confirmed';
    const STATUS_USED = 'used';
    const STATUS_EXPIRED = 'expired';
    const STATUS_REVOKED = 'revoked';

    /**
     * Generate a new authorization session for a user
     *
     * @param User $user
     * @param array $deviceInfo ['ip', 'user_agent']
     * @param int $expiryMinutes
     * @return static
     */
    public static function generate(User $user, array $deviceInfo = [], int $expiryMinutes = 5): self
    {
        // Clean up old expired sessions for this user
        self::cleanupExpired($user->id);

        // Generate unique token and short code
        $token = self::generateUniqueToken();
        $shortCode = self::generateUniqueShortCode();

        // Create session
        return self::create([
            'token' => $token,
            'short_code' => $shortCode,
            'user_id' => $user->id,
            'status' => self::STATUS_PENDING,
            'expires_at' => Carbon::now()->addMinutes($expiryMinutes),
            'device_ip' => $deviceInfo['ip'] ?? request()->ip(),
            'device_user_agent' => $deviceInfo['user_agent'] ?? request()->userAgent(),
            'device_name' => $deviceInfo['name'] ?? null,
        ]);
    }

    /**
     * Generate a unique token
     *
     * @return string
     */
    protected static function generateUniqueToken(): string
    {
        do {
            $token = Str::random(64);
        } while (self::where('token', $token)->exists());

        return $token;
    }

    /**
     * Generate a unique 8-character short code (HBO-style)
     * Format: XXXX-XXXX (uppercase letters and numbers, no confusing chars)
     *
     * @return string
     */
    protected static function generateUniqueShortCode(): string
    {
        // Use only uppercase letters and numbers, exclude confusing characters
        // Excluded: 0, O, 1, I, L to avoid confusion
        $characters = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';

        do {
            // Generate 8 random characters
            $code = '';
            for ($i = 0; $i < 8; $i++) {
                $code .= $characters[random_int(0, strlen($characters) - 1)];
            }

            // Format as XXXX-XXXX
            $shortCode = substr($code, 0, 4) . '-' . substr($code, 4, 4);
        } while (self::where('short_code', $shortCode)->exists());

        return $shortCode;
    }

    /**
     * Find session by short code and validate it
     *
     * @param string $shortCode
     * @return static|null
     */
    public static function findValidShortCode(string $shortCode): ?self
    {
        // Normalize short code (uppercase, remove spaces)
        $shortCode = strtoupper(str_replace(' ', '', $shortCode));

        // Add hyphen if not present
        if (strlen($shortCode) === 8 && strpos($shortCode, '-') === false) {
            $shortCode = substr($shortCode, 0, 4) . '-' . substr($shortCode, 4, 4);
        }

        $session = self::where('short_code', $shortCode)->first();

        if (!$session) {
            return null;
        }

        // Check if expired
        if ($session->isExpired()) {
            $session->markAsExpired();
            return null;
        }

        // Check if already used or revoked
        if (in_array($session->status, [self::STATUS_USED, self::STATUS_REVOKED, self::STATUS_EXPIRED])) {
            return null;
        }

        return $session;
    }

    /**
     * Find session by token and validate it
     *
     * @param string $token
     * @return static|null
     */
    public static function findValidToken(string $token): ?self
    {
        $session = self::where('token', $token)->first();

        if (!$session) {
            return null;
        }

        // Check if expired
        if ($session->isExpired()) {
            $session->markAsExpired();
            return null;
        }

        // Check if already used or revoked
        if (in_array($session->status, [self::STATUS_USED, self::STATUS_REVOKED, self::STATUS_EXPIRED])) {
            return null;
        }

        return $session;
    }

    /**
     * Check if session is expired
     *
     * @return bool
     */
    public function isExpired(): bool
    {
        return Carbon::now()->greaterThan($this->expires_at);
    }

    /**
     * Check if session is pending confirmation
     *
     * @return bool
     */
    public function isPending(): bool
    {
        return $this->status === self::STATUS_PENDING && !$this->isExpired();
    }

    /**
     * Check if session is confirmed and ready to use
     *
     * @return bool
     */
    public function isConfirmed(): bool
    {
        return $this->status === self::STATUS_CONFIRMED && !$this->isExpired();
    }

    /**
     * Confirm the authorization (parent scanned QR on their device)
     *
     * @param string|null $authIp
     * @return bool
     */
    public function confirm(?string $authIp = null): bool
    {
        if (!$this->isPending()) {
            return false;
        }

        $this->status = self::STATUS_CONFIRMED;
        $this->confirmed_at = Carbon::now();
        $this->auth_ip = $authIp ?? request()->ip();

        return $this->save();
    }

    /**
     * Mark session as used (after successful login on new device)
     *
     * @param string $sessionId Winter session ID
     * @return bool
     */
    public function markAsUsed(string $sessionId): bool
    {
        if (!$this->isConfirmed()) {
            return false;
        }

        $this->status = self::STATUS_USED;
        $this->used_at = Carbon::now();
        $this->session_id = $sessionId;
        $this->last_activity_at = Carbon::now();

        return $this->save();
    }

    /**
     * Mark session as expired
     *
     * @return bool
     */
    public function markAsExpired(): bool
    {
        if ($this->status === self::STATUS_EXPIRED) {
            return true;
        }

        $this->status = self::STATUS_EXPIRED;
        return $this->save();
    }

    /**
     * Revoke the session
     *
     * @return bool
     */
    public function revoke(): bool
    {
        $this->status = self::STATUS_REVOKED;
        return $this->save();
    }

    /**
     * Update last activity timestamp
     *
     * @return bool
     */
    public function updateActivity(): bool
    {
        $this->last_activity_at = Carbon::now();
        return $this->save();
    }

    /**
     * Get user-friendly device name
     *
     * @return string
     */
    public function getDeviceNameAttribute(): string
    {
        if ($this->attributes['device_name']) {
            return $this->attributes['device_name'];
        }

        // Parse user agent for friendly name
        $ua = $this->device_user_agent ?? '';

        if (str_contains($ua, 'iPhone')) {
            return 'iPhone';
        } elseif (str_contains($ua, 'iPad')) {
            return 'iPad';
        } elseif (str_contains($ua, 'Android')) {
            return 'Android Device';
        } elseif (str_contains($ua, 'Windows')) {
            return 'Windows PC';
        } elseif (str_contains($ua, 'Macintosh')) {
            return 'Mac';
        } elseif (str_contains($ua, 'Linux')) {
            return 'Linux PC';
        }

        return 'Unknown Device';
    }

    /**
     * Get short device info for display
     *
     * @return string
     */
    public function getDeviceInfoAttribute(): string
    {
        $parts = [];

        if ($this->device_name_attribute) {
            $parts[] = $this->device_name_attribute;
        }

        if ($this->device_ip) {
            $parts[] = $this->device_ip;
        }

        return implode(' • ', $parts) ?: 'No device info';
    }

    /**
     * Get authorization URL for QR code
     *
     * @return string
     */
    public function getAuthUrl(): string
    {
        return url("/device/scan/{$this->token}");
    }

    /**
     * Clean up expired sessions for a user
     *
     * @param int|null $userId If null, cleans up all users
     * @return int Number of sessions cleaned up
     */
    public static function cleanupExpired(?int $userId = null): int
    {
        $query = self::where('expires_at', '<', Carbon::now())
            ->where('status', self::STATUS_PENDING);

        if ($userId) {
            $query->where('user_id', $userId);
        }

        return $query->delete();
    }

    /**
     * Get active devices for a user (sessions that were used)
     *
     * @param int $userId
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public static function getActiveDevices(int $userId)
    {
        return self::where('user_id', $userId)
            ->where('status', self::STATUS_USED)
            ->orderBy('last_activity_at', 'desc')
            ->get();
    }

    /**
     * Scope: Only pending sessions
     */
    public function scopePending($query)
    {
        return $query->where('status', self::STATUS_PENDING);
    }

    /**
     * Scope: Only confirmed sessions
     */
    public function scopeConfirmed($query)
    {
        return $query->where('status', self::STATUS_CONFIRMED);
    }

    /**
     * Scope: Only used sessions (active devices)
     */
    public function scopeUsed($query)
    {
        return $query->where('status', self::STATUS_USED);
    }

    /**
     * Scope: Not expired
     */
    public function scopeNotExpired($query)
    {
        return $query->where('expires_at', '>', Carbon::now());
    }
}
