<?php

namespace Securilex\Authentication\User;

use Symfony\Component\Security\Core\User\AdvancedUserInterface;

interface MutableUserInterface extends AdvancedUserInterface
{

    public function setPassword($password);

    public function setSalt($salt);

    public function setRoles(array $roles);
}