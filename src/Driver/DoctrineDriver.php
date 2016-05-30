<?php

namespace Securilex\Driver;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\SimpleAuthenticatorInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException as UserNotFoundEx;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class DoctrineDriver extends BaseDriver implements SimpleAuthenticatorInterface,
    UserProviderInterface
{
    const NOT_FOUND = 'Username "%s" does not exist.';

    /**
     *
     * @var EntityManager
     */
    protected $em;

    /**
     * The User entity full class name
     * @var string
     */
    protected $userClass;

    /**
     * The column name for the username in the database table
     * @var string
     */
    protected $usernameColumn;

    /**
     * Additional criteria when querying for User
     * @var array
     */
    protected $additionalCriteria;

    /**
     * Authentication Provider
     * @var AuthenticationProviderInterface
     */
    protected $authenticationProvider;

    public function __construct(EntityManager $em, $userClass,
                                $usernameColumn = 'username',
                                array $additionalCriteria = array())
    {
        $this->em                 = $em;
        $this->userClass          = $userClass;
        $this->usernameColumn     = $usernameColumn;
        $this->additionalCriteria = $additionalCriteria;
    }

    /**
     * {@inheritdoc}
     */
    public function getId()
    {
        return 'doctrine';
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthenticationProvider(\Silex\Application $app,
                                              $providerKey)
    {
        if (!$this->authenticationProvider) {
            $this->authenticationProvider = new SimpleAuthenticationProvider($this,
                $app['security.user_provider.'.$providerKey], $providerKey);
        }
        return $this->authenticationProvider;
    }

    /**
     * {@inheritdoc}
     */
    public function getBuiltInUserProvider()
    {
        return $this;
    }

    /**
     * Load User by username
     * @param string $username
     * @return UserInterface
     * @throws UserNotFoundEx
     */
    public function loadUserByUsername($username)
    {
        $user = $this->em->getRepository($this->userClass)->findOneBy(
            array_merge(
                $this->additionalCriteria,
                array($this->usernameColumn => $username)
            )
        );
        if (!$user) {
            $ex = new UserNotFoundEx(sprintf(self::NOT_FOUND, $username));
            $ex->setUsername($username);
            throw $ex;
        }
        return $user;
    }

    /**
     * Refresh the User object
     * @param UserInterface $user
     * @return UserInterface
     */
    public function refreshUser(UserInterface $user)
    {
        $fresh_user = clone $user;
        $fresh_user->eraseCredentials();
        return $fresh_user;
    }

    /**
     * Check if the passed class name is supported or not
     * @param string $class The class name
     * @return boolean Whether the passed class is supported
     */
    public function supportsClass($class)
    {
        if ($class == $this->userClass) {
            return true;
        }
        $c = new \ReflectionClass($class);
        return $c->isSubclassOf($this->userClass);
    }

    /**
     *
     * @param TokenInterface $token
     * @param UserProviderInterface $userProvider
     * @param string $providerKey
     * @return UsernamePasswordToken
     * @throws BadCredentialsException
     */
    public function authenticateToken(TokenInterface $token,
                                      UserProviderInterface $userProvider,
                                      $providerKey)
    {
        $user = $userProvider->loadUserByUsername($token->getUsername());

        if ($this->encoder->isPasswordValid($user, $token->getCredentials())) {
            return new UsernamePasswordToken(
                $user, $user->getPassword(), $providerKey, $user->getRoles()
            );
        }
        throw new BadCredentialsException('The presented password is invalid.');
    }

    /**
     *
     * @param TokenInterface $token
     * @param string $providerKey
     * @return boolean
     */
    public function supportsToken(TokenInterface $token, $providerKey)
    {
        return $token instanceof UsernamePasswordToken && $token->getProviderKey()
            === $providerKey;
    }
}