<?php

namespace Golem15\User\Classes;

use Golem15\User\Facades\Auth;
use Golem15\User\Models\User;

/**
 * FamilyAuth
 *
 * Helper class for handling authentication in a family context with role switching.
 * Provides methods to get the correct user based on role session (parent/child switching).
 */
class FamilyAuth
{
    /**
     * Get the current active user (role session or authenticated user)
     *
     * When using UserPicker, the actual active user might be different from
     * the authenticated user (e.g., parent viewing as child).
     *
     * @return User|null
     */
    public static function getUser(): ?User
    {
        // First try to get role session user (from UserPicker)
        $roleUserId = session('selected_user_id');

        if ($roleUserId) {
            $roleUser = User::find($roleUserId);
            if ($roleUser) {
                return $roleUser;
            }
        }

        // Fallback to authenticated user
        return Auth::getUser();
    }

    /**
     * Get the authenticated user (actual logged-in user)
     *
     * This always returns the user who is logged in,
     * regardless of role switching.
     *
     * @return User|null
     */
    public static function getAuthUser(): ?User
    {
        return Auth::getUser();
    }

    /**
     * Get the current session role (parent or child)
     *
     * @return string|null
     */
    public static function getRole(): ?string
    {
        return session('selected_user_role');
    }

    /**
     * Check if current user is acting as a parent
     *
     * @return bool
     */
    public static function isParent(): bool
    {
        $role = self::getRole();
        return $role === 'parent';
    }

    /**
     * Check if current user is acting as a child
     *
     * @return bool
     */
    public static function isChild(): bool
    {
        $role = self::getRole();
        return $role === 'child';
    }

    /**
     * Check if role switching is active
     *
     * Returns true if the session role user differs from auth user
     *
     * @return bool
     */
    public static function isRoleSwitched(): bool
    {
        $roleUserId = session('selected_user_id');
        $authUser = Auth::getUser();

        if (!$roleUserId || !$authUser) {
            return false;
        }

        return $roleUserId !== $authUser->id;
    }

    /**
     * Get both auth user and role user
     *
     * Useful when you need to know both who is logged in
     * and who they're acting as.
     *
     * @return array ['auth' => User|null, 'role' => User|null]
     */
    public static function getBoth(): array
    {
        return [
            'auth' => self::getAuthUser(),
            'role' => self::getUser(),
        ];
    }

    /**
     * Check if user is authenticated (either auth or role session exists)
     *
     * @return bool
     */
    public static function check(): bool
    {
        return self::getUser() !== null;
    }

    /**
     * Get user ID of current active user
     *
     * @return int|null
     */
    public static function id(): ?int
    {
        $user = self::getUser();
        return $user ? $user->id : null;
    }
}
