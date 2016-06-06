<?php

namespace Securilex\Authentication\User;

use Symfony\Component\Security\Core\User\UserProviderInterface;

interface MutableUserProviderInterface extends UserProviderInterface
{

    public function saveUser(MutableUserInterface $user);

    public function removeUser(MutableUserInterface $user);
}