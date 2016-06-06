<?php

namespace Securilex\Authentication\User;

use Symfony\Component\Security\Core\User\UserInterface;

interface MutableUserInterface extends UserInterface
{

    public function setPassword($password);

    public function setSalt($salt);

    public function setRoles(array $roles);
}