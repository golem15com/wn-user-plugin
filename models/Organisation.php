<?php namespace Golem15\User\Models;

use Model;
use Str;

/**
 * Organisation model (Phase 12, WS-1) — STRUCTURE ONLY, no business logic.
 *
 * Groups members (users) under a shared identity for multi-user self-hostable
 * deployments. The backend RelationController surface (D-11) and all org logic
 * live elsewhere — the Inventory plugin owns org-level AI credentials, and Plan
 * 12-09 binds the members RelationController. This core-plugin model carries NO
 * inbound coupling to the Inventory plugin namespace (Pitfall 5).
 */
class Organisation extends Model
{
    public $table = 'golem15_user_organisations';

    protected $fillable = ['slug', 'name', 'description'];

    public $rules = [
        'name' => 'required',
        'slug' => 'required|alpha_dash|unique:golem15_user_organisations',
    ];

    public $attachOne = [
        'avatar' => \System\Models\File::class,
    ];

    public $hasMany = [
        'members' => [User::class, 'key' => 'organisation_id'],
    ];

    public function beforeValidate()
    {
        if (!$this->slug && $this->name) {
            $this->slug = Str::slug($this->name);
        }
    }
}
