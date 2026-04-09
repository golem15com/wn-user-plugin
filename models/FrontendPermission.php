<?php namespace Golem15\User\Models;

use Winter\Storm\Database\Model;

class FrontendPermission extends Model
{
    use \Winter\Storm\Database\Traits\Validation;

    protected $table = 'golem15_user_frontend_permissions';

    protected $fillable = ['code', 'label', 'tab', 'comment'];

    public $rules = [
        'code'  => 'required|unique:golem15_user_frontend_permissions',
        'label' => 'required',
        'tab'   => 'required',
    ];

    /**
     * Returns permissions grouped by tab, matching the format of BackendAuth::listTabbedPermissions().
     * Each permission is a stdClass with code, label, comment properties.
     *
     * @return array ['Tab Name' => [stdClass, ...], ...]
     */
    public static function listTabbedPermissions()
    {
        $permissions = [];

        foreach (static::orderBy('tab')->orderBy('code')->get() as $record) {
            $obj = new \stdClass;
            $obj->code = $record->code;
            $obj->label = $record->label;
            $obj->comment = $record->comment ?? '';

            $permissions[$record->tab][] = $obj;
        }

        return $permissions;
    }
}
