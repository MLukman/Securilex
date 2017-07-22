<?php

namespace Securilex\Authentication\User;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\User\User;

class SQLite3UserProviderTest extends TestCase
{
    protected $instance = null;

    protected function setUp()
    {
        if (!$this->instance) {
            $this->instance = new Sqlite3UserProvider(new \SQLite3(':memory:'));
        }
    }

    protected function tearDown()
    {
        if ($this->instance) {
            $this->instance = null;
        }
        parent::tearDown();
    }

    /**
     * @covers SQLite3UserProvider::saveUser
     */
    public function testSaveUser()
    {
        $countBefore = $this->instance->countAll();
        $this->instance->saveUser(new User('User'.\rand(10000, 99999), 'password'));
        $countAfter  = $this->instance->countAll();
        $this->assertEquals(1, $countAfter - $countBefore);
    }

    /**
     * @covers SQLite3UserProvider::loadUserByUsername
     */
    public function testLoadUserByUsername()
    {
        $this->instance->saveUser(new User('User01', 'password'));
        $user = $this->instance->loadUserByUsername('User01');
        $this->assertEquals('User01', $user->getUsername());
    }

    /**
     * @covers SQLite3UserProvider::refreshUser
     */
    public function testRefreshUser()
    {
        $user = new User('User02', 'Password02');
        $this->assertEquals('User02', $this->instance->refreshUser($user));
    }

    /**
     * @covers SQLite3UserProvider::removeUser
     */
    public function testRemoveUser()
    {
        $this->instance->saveUser(new User('User01', 'password'));
        $countBefore = $this->instance->countAll();
        $this->instance->removeUser(new User('User01', 'password'));
        $countAfter  = $this->instance->countAll();
        $this->assertEquals(-1, $countAfter - $countBefore);
    }
}