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
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * LdapBindAuthenticationFactory creates instances of SimpleAuthenticationProvider that
 * authenticates plain text user password
 * using information from an instance of \Silex\Application, UserProviderInterface and a provider key
 */
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
        return new SimpleAuthenticationProvider($this, $userProvider,
            $providerKey);
    }

    /**
     * Get the unique id of this instance of authentication factory.
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Attempt to authenticate the provided token using the provided user provider.
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
     * @param string $providerKey
     * @return type
     */
    public function supportsToken(TokenInterface $token, $providerKey)
    {
        return $token instanceof UsernamePasswordToken && $token->getProviderKey()
            === $providerKey;
    }
}