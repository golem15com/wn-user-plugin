<?php namespace Golem15\User\Models;

use Winter\Storm\Auth\Models\Group as GroupBase;
use ApplicationException;

/**
 * User Group Model
 */
class UserGroup extends GroupBase
{
    const GROUP_GUEST = 'guest';
    const GROUP_REGISTERED = 'registered';

    /**
     * @var string The database table used by the model.
     */
    protected $table = 'user_groups';

    /**
     * Validation rules
     */
    public $rules = [
        'name' => 'required|between:3,64',
        'code' => 'required|regex:/^[a-zA-Z0-9_\-]+$/|unique:user_groups',
    ];

    /**
     * @var array Relations
     */
    public $belongsToMany = [
        'users'       => [User::class, 'table' => 'users_groups'],
        'users_count' => [User::class, 'table' => 'users_groups', 'count' => true]
    ];

    /**
     * @var array The attributes that are mass assignable.
     */
    protected $fillable = [
        'name',
        'code',
        'description',
        'permissions',
    ];

    /**
     * @var array List of attribute names which are json encoded and decoded from the database.
     */
    protected $jsonable = ['permissions'];

    protected static $guestGroup = null;

    /**
     * Returns the guest user group.
     * @return Golem15\User\Models\UserGroup
     */
    public static function getGuestGroup()
    {
        if (self::$guestGroup !== null) {
            return self::$guestGroup;
        }

        $group = self::where('code', self::GROUP_GUEST)->first() ?: false;

        return self::$guestGroup = $group;
    }
}
