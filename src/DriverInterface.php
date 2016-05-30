<?php

namespace Securilex;

interface DriverInterface
{

    /**
     * return string Id to identify this driver
     */
    public function getId();

    /**
     * Get Authentication Provider
     * @param \Silex\Application $app The application
     * @param string $providerKey Provider key (usually needed by the authentication provider)
     * @return \Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface
     */
    public function getAuthenticationProvider(\Silex\Application $app,
                                              $providerKey);

    /**
     * Get built-in User Provider, if any, otherwise return null
     * @return \Symfony\Component\Security\Core\User\UserProviderInterface|null
     */
    public function getBuiltInUserProvider();

    /**
     * Register the Driver
     * @param \Silex\Application $app
     */
    public function register(\Silex\Application $app);
}