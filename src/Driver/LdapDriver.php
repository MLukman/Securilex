<?php

namespace Securilex\Driver;

use Symfony\Component\Ldap\Ldap;
use Symfony\Component\Security\Core\Authentication\Provider\LdapBindAuthenticationProvider;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\Security\Core\User\User;

class LdapDriver extends BaseDriver
{
    /**
     * Authentication Provider
     * @var AuthenticationProviderInterface
     */
    protected $authenticationProvider;

    /**
     *
     * @var \Symfony\Component\Ldap\LdapInterface
     */
    protected $ldapClient;

    /**
     *
     * @var string
     */
    protected $dnString;

    /**
     *
     * @var InMemoryUserProvider
     */
    protected $userProvider;

    public function __construct($host, $port, $dnString)
    {
        $this->userProvider = new InMemoryUserProvider();
        $this->ldapClient   = Ldap::create('ext_ldap',
                array('host' => $host, 'port' => $port, 'version' => 3));
        $this->dnString     = $dnString;
    }

    /**
     * Add a user to the list of authenticated users
     * @param string $userid The user id
     * @param array $role The array of user roles: ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN
     */
    public function addUser($userid, array $role = array('ROLE_ADMIN'))
    {
        $this->userProvider->createUser(new User($userid, null, $role));
    }

    public function getAuthenticationProvider(\Silex\Application $app,
                                              $providerKey)
    {
        if (!$this->authenticationProvider) {
            $this->authenticationProvider = new LdapBindAuthenticationProvider($this->userProvider,
                $app['security.user_checker'], $providerKey, $this->ldapClient,
                $this->dnString);
        }
        return $this->authenticationProvider;
    }

    public function getBuiltInUserProvider()
    {
        return $this->userProvider;
    }

    public function getId()
    {
        return 'ldap';
    }
}