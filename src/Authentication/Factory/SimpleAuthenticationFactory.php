<?php
/**
 * This file is part of the Securilex library for Silex framework.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @package Securilex\Authentication\Factory
 * @author Muhammad Lukman Nasaruddin <anatilmizun@gmail.com>
 * @link https://github.com/MLukman/Securilex Securilex Github
 * @link https://packagist.org/packages/mlukman/securilex Securilex Packagist
 */

namespace Securilex\Authentication\Factory;

use Securilex\Authentication\AuthenticationFactoryInterface;
use Symfony\Component\Security\Core\Authentication\Provider\SimpleAuthenticationProvider;
use Symfony\Component\Security\Core\Authentication\SimpleAuthenticatorInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * SimpleAuthenticationFactory creates instances of SimpleAuthenticationProvider using
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
     * The simple authenticator object
     * @var SimpleAuthenticatorInterface
     */
    protected $simpleAuthenticator;

    /**
     * Construct an instance.
     * @staticvar int $instanceId
     * @param SimpleAuthenticatorInterface $simpleAuthenticator The simple authenticator instance
     * which will actually do the authentication of users
     */
    public function __construct(SimpleAuthenticatorInterface $simpleAuthenticator)
    {
        static $instanceId         = 0;
        $this->id                  = 'simple'.($instanceId++);
        $this->simpleAuthenticator = $simpleAuthenticator;
    }

    /**
     * Create Authentication Provider instance.
     * @param \Silex\Application $app
     * @param UserProviderInterface $userProvider
     * @param string $providerKey
     * @return SimpleAuthenticationProvider
     */
    public function createAuthenticationProvider(\Silex\Application $app,
                                                 UserProviderInterface $userProvider,
                                                 $providerKey)
    {
        return new SimpleAuthenticationProvider($this->simpleAuthenticator,
            $userProvider, $providerKey);
    }

    /**
     * Get the unique id of this instance of authentication factory.
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }
}