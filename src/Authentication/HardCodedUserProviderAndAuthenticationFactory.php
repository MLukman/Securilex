<?php

namespace Securilex\Authentication;

use Symfony\Component\Security\Core\Authentication\Provider\SimpleAuthenticationProvider;
use Symfony\Component\Security\Core\Authentication\SimpleAuthenticatorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * HardCodedUserProviderAndAuthenticationFactory combines both Authentication Factory and UserProvider
 * into single instance. Use this class for a simple hard-coded list of users.
 */
class HardCodedUserProviderAndAuthenticationFactory implements AuthenticationFactoryInterface,
    UserProviderInterface, SimpleAuthenticatorInterface
{
    /**
     * Id of this factory
     * @var string
     */
    protected $id;

    /**
     * The UserProvider used internally to stored the users
     * @var InMemoryUserProvider
     */
    protected $userProvider;

    public function __construct()
    {
        static $instanceId  = 0;
        $this->id           = 'hardcoded'.($instanceId++);
        $this->userProvider = new InMemoryUserProvider();
    }

    /**
     * {@inheritdoc}
     */
    public function createAuthenticationProvider(\Silex\Application $app,
                                                 UserProviderInterface $userProvider,
                                                 $providerKey)
    {
        return new SimpleAuthenticationProvider($this, $userProvider,
            $providerKey);
    }

    /**
     * {@inheritdoc}
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Add a new user to the list of hard-coded users.
     * @param string $username Username
     * @param string $password Plain-text password
     * @param array $roles
     */
    public function addUser($username, $password, array $roles)
    {
        $this->userProvider->createUser(new User($username, $password, $roles));
    }

    /**
     * Load user by username.
     * @param string $username
     * @return UserInterface
     * @throws UsernameNotFoundException
     */
    public function loadUserByUsername($username)
    {
        return $this->userProvider->loadUserByUsername($username);
    }

    /**
     * Refresh user.
     * @param UserInterface $user
     * @return UserInterface
     */
    public function refreshUser(UserInterface $user)
    {
        return $this->userProvider->refreshUser($user);
    }

    /**
     * Determine if the provided class name is supported or not.
     * @param string $class
     * @return boolean
     */
    public function supportsClass($class)
    {
        return $this->userProvider->supportsClass($class);
    }

    /**
     * Attempt to authenticate the provided token using the provided user provider.
     * @param TokenInterface $token
     * @param UserProviderInterface $userProvider
     * @param type $providerKey
     * @return UsernamePasswordToken
     * @throws BadCredentialsException
     */
    public function authenticateToken(TokenInterface $token,
                                      UserProviderInterface $userProvider,
                                      $providerKey)
    {
        if (($user = $userProvider->loadUserByUsername($token->getUsername())) && ($user->getPassword()
            == $token->getCredentials())) {
            return new UsernamePasswordToken(
                $user, $user->getPassword(), $providerKey, $user->getRoles()
            );
        }
        throw new BadCredentialsException('The presented password is invalid.');
    }

    /**
     * Determine if this instance supports the provided token.
     * @param TokenInterface $token
     * @param type $providerKey
     * @return type
     */
    public function supportsToken(TokenInterface $token, $providerKey)
    {
        return $token instanceof UsernamePasswordToken && $token->getProviderKey()
            === $providerKey;
    }
}