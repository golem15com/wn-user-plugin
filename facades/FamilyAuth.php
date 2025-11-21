<?php

namespace Golem15\User\Facades;

use Winter\Storm\Support\Facade;

/**
 * FamilyAuth Facade
 *
 * @method static \Golem15\User\Models\User|null getUser() Get the current active user (role session or authenticated user)
 * @method static \Golem15\User\Models\User|null getAuthUser() Get the authenticated user (actual logged-in user)
 * @method static string|null getRole() Get the current session role (parent or child)
 * @method static bool isParent() Check if current user is acting as a parent
 * @method static bool isChild() Check if current user is acting as a child
 * @method static bool isRoleSwitched() Check if role switching is active
 * @method static array getBoth() Get both auth user and role user
 * @method static bool check() Check if user is authenticated
 * @method static int|null id() Get user ID of current active user
 *
 * @see \Golem15\User\Classes\FamilyAuth
 */
class FamilyAuth extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return \Golem15\User\Classes\FamilyAuth::class;
    }
}
