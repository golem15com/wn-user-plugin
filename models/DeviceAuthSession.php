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
 * @property string|null $code_challenge PKCE S256 challenge (RFC 7636); non-null = redeemable session
 * @property Carbon|null $denied_at
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
        'code_challenge',
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
        'denied_at',
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
     * Poll interval (seconds) advertised to API clients of the redeemable flow
     * (RFC 8628 style "interval").
     */
    public const POLL_INTERVAL_SECONDS = 3;

    /**
     * Longest device name cleanDisplayName() returns, in characters.
     */
    public const DISPLAY_NAME_MAX = 64;

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

        // A redeemable session must be redeemed shortly after the browser confirms
        // it: the confirmed grant lives for the redeem window only. Sessions
        // without a code_challenge keep their original expires_at.
        if ($this->isRedeemable()) {
            $this->expires_at = Carbon::now()->addSeconds(self::redeemTtlSeconds());
        }

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
     * Whether this session was created with a PKCE code_challenge, i.e. it can only
     * be completed by POST devices/redeem with the matching code_verifier. Every
     * rule added for the redeem flow is gated on this.
     *
     * @return bool
     */
    public function isRedeemable(): bool
    {
        return $this->code_challenge !== null && $this->code_challenge !== '';
    }

    /**
     * Verify a PKCE code_verifier against the stored S256 challenge
     * (RFC 7636 section 4.6), in constant time.
     *
     * @param string $verifier
     * @return bool
     */
    public function verifyCodeVerifier(string $verifier): bool
    {
        if (!$this->isRedeemable() || !preg_match('/^[A-Za-z0-9\-._~]{43,128}$/', $verifier)) {
            return false;
        }

        $computed = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        return hash_equals((string) $this->code_challenge, $computed);
    }

    /**
     * Pending window for new device sessions, in minutes (Setting
     * device_auth_pending_ttl, default 5 as before).
     *
     * @return int
     */
    public static function pendingTtlMinutes(): int
    {
        return max(1, (int) Settings::get('device_auth_pending_ttl', 5));
    }

    /**
     * Redeem window after confirm for redeemable sessions, in seconds (Setting
     * device_auth_redeem_ttl, default 60).
     *
     * @return int
     */
    public static function redeemTtlSeconds(): int
    {
        return max(10, (int) Settings::get('device_auth_redeem_ttl', 60));
    }

    /**
     * Status as reported to API clients: revoked reads as "denied", and a pending
     * or confirmed session past its window reads as "expired".
     *
     * @return string
     */
    public function publicStatus(): string
    {
        if ($this->status === self::STATUS_REVOKED) {
            return 'denied';
        }

        if (in_array($this->status, [self::STATUS_PENDING, self::STATUS_CONFIRMED], true) && $this->isExpired()) {
            return self::STATUS_EXPIRED;
        }

        return (string) $this->status;
    }

    /**
     * Whole seconds until expires_at, never negative.
     *
     * @return int
     */
    public function secondsLeft(): int
    {
        if (!$this->expires_at) {
            return 0;
        }

        $now = Carbon::now();

        return $this->expires_at->greaterThan($now) ? (int) $now->diffInSeconds($this->expires_at) : 0;
    }

    /**
     * Deny a pending session (a signed-in user refused it in the browser).
     *
     * Stored as status "revoked" plus denied_at: the status column is a strict
     * ENUM, and revoked sessions are already excluded by findValidToken() /
     * findValidShortCode(), so a denied session can never be confirmed later.
     *
     * @return bool false when the session is not pending
     */
    public function deny(): bool
    {
        if (!$this->isPending()) {
            return false;
        }

        $this->status = self::STATUS_REVOKED;
        $this->denied_at = Carbon::now();

        return $this->save();
    }

    /**
     * Split a user agent into the app (browser family) and OS family, using
     * TrustedDevice::parseDeviceName(). Unknown parts are null.
     *
     * @param string|null $userAgent
     * @return array{app: ?string, os: ?string}
     */
    public static function userAgentParts(?string $userAgent): array
    {
        $userAgent = trim((string) $userAgent);
        if ($userAgent === '') {
            return ['app' => null, 'os' => null];
        }

        $parts = explode(' on ', TrustedDevice::parseDeviceName($userAgent), 2);
        $app = $parts[0] ?? null;
        $os = $parts[1] ?? null;

        return [
            'app' => ($app === null || $app === 'Unknown Browser') ? null : $app,
            'os' => ($os === null || $os === 'Unknown OS') ? null : $os,
        ];
    }

    /**
     * A caller-supplied device name made safe to show to a person: a confirm page
     * or an email (Markdown + HTML). device_name comes from the unauthenticated
     * initiate call, so it is treated as hostile.
     *
     * Control and format characters (NUL, tabs, bidi overrides, zero-width) are
     * removed. Whitespace is collapsed. Then only a small display character set is
     * kept: letters, combining marks, digits, space, ( ) ' and -. That drops every
     * Markdown or HTML metacharacter ([ ] < > * _ ` # ! | ~ &), and also the URL
     * and domain characters (: / . @), so the result cannot render as a link or as
     * markup, and a mail client cannot auto-link it. The result is capped at
     * DISPLAY_NAME_MAX characters. Empty or non-string input gives null.
     *
     * Additive helper. It does not change what is stored or what the
     * device_name accessor returns.
     *
     * @param mixed $name
     * @return string|null
     */
    public static function cleanDisplayName(mixed $name): ?string
    {
        if (!is_string($name)) {
            return null;
        }

        $clean = preg_replace('/[\p{Cc}\p{Cf}]/u', '', $name);
        if (!is_string($clean)) {
            return null; // invalid UTF-8
        }

        $clean = (string) preg_replace('/\s+/u', ' ', $clean);
        $clean = (string) preg_replace("/[^\\p{L}\\p{M}\\p{N} ()'\\-]/u", '', $clean);
        $clean = trim((string) preg_replace('/ {2,}/', ' ', $clean));
        $clean = trim(mb_substr($clean, 0, self::DISPLAY_NAME_MAX));

        return $clean === '' ? null : $clean;
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
