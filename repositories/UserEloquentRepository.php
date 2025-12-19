<?php

namespace Golem15\User\Repositories;

use Golem15\User\Contracts\UserRepository;
use Golem15\User\Models\User;

class UserEloquentRepository implements UserRepository
{

    public function findById($id): ?User
    {
        return User::where('id', $id)->rememberForever(self::CACHE_KEY_PREFIX . $id)->first();
    }
}
