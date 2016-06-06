<?php

namespace Securilex\Authentication\Factory;

use Securilex\Authentication\AuthenticationFactoryInterface;
use Securilex\Authentication\User\MutableUserInterface;
use Securilex\Authentication\User\MutableUserProviderInterface;
use Symfony\Component\Security\Core\Authentication\Provider\SimpleAuthenticationProvider;
use Symfony\Component\Security\Core\Authentication\SimpleAuthenticatorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * InitializableAuthenticationProvider allows initializing a user with the current password
 * when the password associated with the user matched with a specific string.
 * Important: this authentication factory requires user provider to implements MutableUserProviderInterface.
 */
class InitializableAuthenticationFactory implements AuthenticationFactoryInterface,
    SimpleAuthenticatorInterface
{
    /**
     * Id of this factory
     * @var string
     */
    protected $id;
    protected $initPassword;
    protected $passwordEncoder;

    public function __construct(PasswordEncoderInterface $passwordEncoder,
                                $initPassword = '')
    {
        static $instanceId     = 0;
        $this->id              = 'init'.($instanceId++);
        $this->initPassword    = $initPassword;
        $this->passwordEncoder = $passwordEncoder;
    }

    /**
     * {@inheritdoc}
     */
    public function createAuthenticationProvider(\Silex\Application $app,
                                                 UserProviderInterface $userProvider,
                                                 $providerKey)
    {
        if (!($userProvider instanceof MutableUserProviderInterface)) {
            throw new \InvalidArgumentException(sprintf(
                'InitializableAuthenticationFactory expects the user provider to be an instance of MutableUserProviderInterface, received %s instead.',
                get_class($userProvider)));
        }
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
        if (($user = $userProvider->loadUserByUsername($token->getUsername()))) {
            $userPassword     = $user->getPassword();
            $tokenCredentials = $token->getCredentials();
            if ($userPassword == $this->initPassword && $user instanceof MutableUserInterface
                && $userProvider instanceof MutableUserProviderInterface) {
                // set both salt & password
                $user->setSalt(substr(md5(rand(1, 10000)), 0, 5));
                $user->setPassword($this->passwordEncoder->encodePassword($tokenCredentials,
                        $user->getSalt()));
                // save the user
                $userProvider->saveUser($user);
                // return it
                return new UsernamePasswordToken(
                    $user, $user->getPassword(), $providerKey, $user->getRoles()
                );
            } else if ($this->passwordEncoder->isPasswordValid($userPassword,
                    $tokenCredentials, $user->getSalt())) {
                return new UsernamePasswordToken(
                    $user, $userPassword, $providerKey, $user->getRoles()
                );
            }
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