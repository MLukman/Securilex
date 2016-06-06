<?php

namespace Securilex\Authentication\Factory;

use Securilex\Authentication\AuthenticationFactoryInterface;
use Symfony\Component\Ldap\Ldap;
use Symfony\Component\Ldap\LdapInterface;
use Symfony\Component\Security\Core\Authentication\Provider\LdapBindAuthenticationProvider;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * LdapBindAuthenticationFactory creates instances of LdapBindAuthenticationProvider
 * information from an instance of \Silex\Application, UserProviderInterface and a provider key
 */
class LdapBindAuthenticationFactory implements AuthenticationFactoryInterface
{
    /**
     * Id of this factory
     * @var string
     */
    protected $id;

    /**
     *
     * @var LdapInterface
     */
    protected $ldapClient;

    /**
     *
     * @var string
     */
    protected $dnString;

    public function __construct($host, $port, $dnString, $version = 3)
    {
        static $instanceId = 0;
        $this->id          = 'ldap'.($instanceId++);
        $this->ldapClient  = Ldap::create('ext_ldap',
                array('host' => $host, 'port' => $port, 'version' => $version));
        $this->dnString    = $dnString;
    }

    /**
     * {@inheritdoc}
     */
    public function createAuthenticationProvider(\Silex\Application $app,
                                                 UserProviderInterface $userProvider,
                                                 $providerKey)
    {
        return new LdapBindAuthenticationProvider($userProvider,
            $app['security.user_checker'], $providerKey, $this->ldapClient,
            $this->dnString);
    }

    /**
     * {@inheritdoc}
     */
    public function getId()
    {
        return $this->id;
    }
}