<?php

namespace Securilex\Authentication\Factory;

use Securilex\Authentication\AuthenticationFactoryInterface;
use Symfony\Component\Security\Core\Authentication\Provider\SimpleAuthenticationProvider;
use Symfony\Component\Security\Core\Authentication\SimpleAuthenticatorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class PlaintextPasswordAuthenticationFactory implements AuthenticationFactoryInterface,
    SimpleAuthenticatorInterface
{
    /**
     * Id of this factory
     * @var string
     */
    protected $id;

    /**
     * Construct an instance.
     * @staticvar int $instanceId
     */
    public function __construct()
    {
        static $instanceId = 0;
        $this->id          = 'plain'.($instanceId++);
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