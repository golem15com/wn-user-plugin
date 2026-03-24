<?php

namespace Golem15\User\Models;

use Illuminate\Support\Facades\Hash;
use Model;

/**
 * TwoFactorRecoveryCode Model
 *
 * Single-use backup codes for 2FA account recovery.
 *
 * @property int $id
 * @property int $user_id
 * @property string $code
 * @property \Carbon\Carbon|null $used_at
 * @property \Carbon\Carbon $created_at
 *
 * @property User $user
 */
class TwoFactorRecoveryCode extends Model
{
    public $table = 'golem15_user_two_factor_recovery_codes';

    public $timestamps = false;

    protected $guarded = ['*'];

    protected $fillable = [
        'user_id',
        'code',
        'used_at',
        'created_at',
    ];

    protected $dates = [
        'used_at',
        'created_at',
    ];

    public $belongsTo = [
        'user' => [User::class, 'key' => 'user_id'],
    ];

    /**
     * Characters used for recovery code generation.
     * Excludes confusing characters: 0, O, 1, I, L
     */
    const CODE_CHARACTERS = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';

    /**
     * Generate a set of recovery codes for a user.
     * Deletes any existing unused codes first.
     *
     * @param int $userId
     * @param int $count
     * @return array Plaintext codes (shown to user once)
     */
    public static function generateForUser(int $userId, int $count = 10): array
    {
        // Delete all existing codes for this user
        self::where('user_id', $userId)->delete();

        $plaintextCodes = [];
        $characters = self::CODE_CHARACTERS;
        $charLen = strlen($characters);

        for ($i = 0; $i < $count; $i++) {
            // Generate XXXXX-XXXXX format
            $part1 = '';
            $part2 = '';
            for ($j = 0; $j < 5; $j++) {
                $part1 .= $characters[random_int(0, $charLen - 1)];
                $part2 .= $characters[random_int(0, $charLen - 1)];
            }
            $plaintext = $part1 . '-' . $part2;
            $plaintextCodes[] = $plaintext;

            self::create([
                'user_id' => $userId,
                'code' => Hash::make($plaintext),
                'created_at' => now(),
            ]);
        }

        return $plaintextCodes;
    }

    /**
     * Verify a recovery code and mark it as used.
     *
     * @param int $userId
     * @param string $code
     * @return bool
     */
    public static function verifyAndConsume(int $userId, string $code): bool
    {
        $code = strtoupper(str_replace(' ', '', $code));

        $unusedCodes = self::where('user_id', $userId)
            ->whereNull('used_at')
            ->get();

        foreach ($unusedCodes as $storedCode) {
            if (Hash::check($code, $storedCode->code)) {
                $storedCode->used_at = now();
                $storedCode->save();
                return true;
            }
        }

        return false;
    }

    /**
     * Count remaining unused codes for a user.
     */
    public static function remainingCount(int $userId): int
    {
        return self::where('user_id', $userId)
            ->whereNull('used_at')
            ->count();
    }

    public function scopeUnused($query)
    {
        return $query->whereNull('used_at');
    }
}
