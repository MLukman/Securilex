<?php

namespace Securilex\Authentication;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Authentication Factory creates instances of Authentication Providers using
 * information from an instance of \Silex\Application, UserProviderInterface and a provider key
 */
interface AuthenticationFactoryInterface
{

    /**
     * Create Authentication Provider instance.
     * @param \Silex\Application $app
     * @param UserProviderInterface $userProvider
     * @param string $providerKey
     * @return AuthenticationProviderInterface
     */
    public function createAuthenticationProvider(\Silex\Application $app,
                                                 UserProviderInterface $userProvider,
                                                 $providerKey);

    /**
     * Get the unique id of this instance of authentication factory.
     * @return string
     */
    public function getId();
}