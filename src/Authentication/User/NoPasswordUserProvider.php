<?php

namespace Securilex\Authentication\User;

use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\Security\Core\User\User;

class NoPasswordUserProvider extends InMemoryUserProvider
{

    public function addUser($username, array $roles)
    {
        $this->createUser(new User($username, null, $roles));
    }
}