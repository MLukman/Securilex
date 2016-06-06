<?php

namespace Securilex\Authentication\Factory;

use Securilex\Authentication\AuthenticationFactoryInterface;
use Symfony\Component\Security\Core\Authentication\Provider\SimpleAuthenticationProvider;
use Symfony\Component\Security\Core\Authentication\SimpleAuthenticatorInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * SimpleAuthenticationFactory creates instances of SimpleAuthenticationProvider
 * information from an instance of \Silex\Application, UserProviderInterface and a provider key
 */
class SimpleAuthenticationFactory implements AuthenticationFactoryInterface
{
    /**
     * Id of this factory
     * @var string
     */
    protected $id;

    /**
     *
     * @var SimpleAuthenticatorInterface
     */
    protected $simpleAuthenticator;

    public function __construct(SimpleAuthenticatorInterface $simpleAuthenticator)
    {
        static $instanceId         = 0;
        $this->id                  = 'simple'.($instanceId++);
        $this->simpleAuthenticator = $simpleAuthenticator;
    }

    /**
     * {@inheritdoc}
     */
    public function createAuthenticationProvider(\Silex\Application $app,
                                                 UserProviderInterface $userProvider,
                                                 $providerKey)
    {
        return new SimpleAuthenticationProvider($this->simpleAuthenticator,
            $userProvider, $providerKey);
    }

    /**
     * {@inheritdoc}
     */
    public function getId()
    {
        return $this->id;
    }
}