<?php

namespace Securilex\Authentication\User;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * UserProviderSegmentalizer segmentalizes an instance of User Provider into segments
 * based on filter functions. This is useful for a single User Provider that requires
 * separate Authentication Providers for different segments of the users
 * (e.g. authenticate using LDAP vs authenticate using stored password)
 */
class UserProviderSegmentalizer implements UserProviderInterface
{
    /**
     * @var UserProviderInterface
     */
    protected $userProvider;
    protected $cachedUsers = array();

    /**
     * Construct an instance using the provided source User Provider.
     * @param UserProviderInterface $userProvider The source User Provider
     */
    public function __construct(UserProviderInterface $userProvider)
    {
        $this->userProvider = $userProvider;
    }

    /**
     * Create an instance of UserProviderSegment using the provided filter funtion.
     *
     * @param \Securilex\Authentication\callable $filter
     * @return \Securilex\Authentication\UserProviderSegment
     */
    public function createSegment(callable $filter)
    {
        return new UserProviderSegment($this, $filter);
    }

    /**
     * Get user from cached, otherwise get it from the source User Provider.
     * @param type $username
     * @return type
     */
    public function loadUserByUsername($username)
    {
        if (!isset($this->cachedUsers[$username])) {
            $this->cachedUsers[$username] = $this->userProvider->loadUserByUsername($username);
        }
        return $this->cachedUsers[$username];
    }

    /**
     * Refresh user using source User Provider.
     * @param UserInterface $user
     * @return UserInterface
     */
    public function refreshUser(UserInterface $user)
    {
        $username                     = $user->getUsername();
        $this->cachedUsers[$username] = $this->userProvider->refreshUser($user);
        return $this->cachedUsers[$username];
    }

    /**
     * Invoke the source UserProvider::supportsClass method.
     * @param type $class
     * @return type
     */
    public function supportsClass($class)
    {
        return $this->userProvider->supportsClass($class);
    }
}