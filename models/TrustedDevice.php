<?php

namespace Golem15\User\Models;

use Carbon\Carbon;
use Illuminate\Support\Str;
use Model;

class TrustedDevice extends Model
{
    public $table = 'golem15_user_trusted_devices';

    protected $fillable = [
        'user_id',
        'token',
        'device_name',
        'ip_address',
        'trusted_until',
        'last_used_at',
    ];

    protected $dates = [
        'trusted_until',
        'last_used_at',
        'created_at',
        'updated_at',
    ];

    public $belongsTo = [
        'user' => [User::class, 'key' => 'user_id'],
    ];

    /**
     * Create a trusted device record for a user.
     */
    public static function createForUser(User $user, int $ttlDays, ?string $userAgent = null, ?string $ipAddress = null): self
    {
        return static::create([
            'user_id' => $user->id,
            'token' => static::generateUniqueToken(),
            'device_name' => $userAgent ? static::parseDeviceName($userAgent) : 'Unknown Device',
            'ip_address' => $ipAddress,
            'trusted_until' => Carbon::now()->addDays($ttlDays),
        ]);
    }

    /**
     * Find a valid (non-expired) trusted device by token.
     */
    public static function findValidToken(string $token): ?self
    {
        return static::where('token', $token)
            ->where('trusted_until', '>', Carbon::now())
            ->first();
    }

    /**
     * Delete expired trusted device records.
     */
    public static function cleanupExpired(?int $userId = null): int
    {
        $query = static::where('trusted_until', '<', Carbon::now());

        if ($userId) {
            $query->where('user_id', $userId);
        }

        return $query->delete();
    }

    /**
     * Generate a unique 64-character token.
     */
    protected static function generateUniqueToken(): string
    {
        do {
            $token = Str::random(64);
        } while (static::where('token', $token)->exists());

        return $token;
    }

    /**
     * Parse a user-agent string into a human-readable device name.
     * Extracts browser family + OS family only (no versions — survives updates).
     */
    public static function parseDeviceName(string $userAgent): string
    {
        // Browser detection (order matters — check specific before generic)
        $browser = 'Unknown Browser';
        if (preg_match('/Edg[e\/]/i', $userAgent)) {
            $browser = 'Edge';
        } elseif (preg_match('/OPR|Opera/i', $userAgent)) {
            $browser = 'Opera';
        } elseif (preg_match('/Vivaldi/i', $userAgent)) {
            $browser = 'Vivaldi';
        } elseif (preg_match('/Brave/i', $userAgent)) {
            $browser = 'Brave';
        } elseif (preg_match('/Chrome|CriOS/i', $userAgent)) {
            $browser = 'Chrome';
        } elseif (preg_match('/Safari/i', $userAgent) && !preg_match('/Chrome/i', $userAgent)) {
            $browser = 'Safari';
        } elseif (preg_match('/Firefox|FxiOS/i', $userAgent)) {
            $browser = 'Firefox';
        }

        // OS detection
        $os = 'Unknown OS';
        if (preg_match('/Windows/i', $userAgent)) {
            $os = 'Windows';
        } elseif (preg_match('/Macintosh|Mac OS/i', $userAgent)) {
            $os = 'macOS';
        } elseif (preg_match('/Android/i', $userAgent)) {
            $os = 'Android';
        } elseif (preg_match('/iPhone|iPad|iPod/i', $userAgent)) {
            $os = 'iOS';
        } elseif (preg_match('/Linux/i', $userAgent)) {
            $os = 'Linux';
        } elseif (preg_match('/CrOS/i', $userAgent)) {
            $os = 'ChromeOS';
        }

        return "{$browser} on {$os}";
    }
}
