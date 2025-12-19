<?php

namespace Golem15\User\Contracts;

use Golem15\User\Models\User;

interface UserRepository
{
    public const CACHE_KEY_PREFIX = 'golem15_user_';
    public function findById($id): ?User;
}
