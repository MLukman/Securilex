<?php

namespace Securilex\Authentication\User;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\User\User;

class AnyUserProviderTest extends TestCase
{
    protected $instance = null;

    protected function setUp()
    {
        if (!$this->instance) {
            $this->instance = new AnyUserProvider();
        }
    }

    public function testLoadUserByUsername()
    {
        $user = $this->instance->loadUserByUsername('User01');
        $this->assertEquals('User01', $user->getUsername());
    }

    public function testRefreshUser()
    {
        $user = new User('User02', 'Password02');
        $this->assertEquals('User02', $this->instance->refreshUser($user));
    }
}