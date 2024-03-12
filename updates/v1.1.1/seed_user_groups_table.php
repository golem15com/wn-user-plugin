<?php namespace Golem15\User\Updates;

use Golem15\User\Models\UserGroup;
use Winter\Storm\Database\Updates\Seeder;

class SeedUserGroupsTable extends Seeder
{
    public function run()
    {
        UserGroup::create([
            'name' => 'Guest',
            'code' => 'guest',
            'description' => 'Default group for guest users.'
        ]);

        UserGroup::create([
            'name' => 'Registered',
            'code' => 'registered',
            'description' => 'Default group for registered users.'
        ]);
    }
}
