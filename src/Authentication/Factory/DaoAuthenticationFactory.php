<?php

namespace Securilex\Authentication\Factory;

use Securilex\Authentication\AuthenticationFactoryInterface;
use Symfony\Component\Security\Core\Authentication\Provider\DaoAuthenticationProvider;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * DaoAuthenticationFactory creates instances of DaoAuthenticationProvider
 * using information from an instance of \Silex\Application and a provider key
 */
class DaoAuthenticationFactory implements AuthenticationFactoryInterface
{
    /**
     * Id of this factory
     * @var string
     */
    protected $id;

    /**
     *
     * @var EncoderFactoryInterface
     */
    protected $encoderFactory;

    public function __construct(EncoderFactoryInterface $encoderFactory = null)
    {
        static $instanceId    = 0;
        $this->id             = 'dao'.($instanceId++);
        $this->encoderFactory = $encoderFactory;
    }

    /**
     * {@inheritdoc}
     */
    public function createAuthenticationProvider(\Silex\Application $app,
                                                 UserProviderInterface $userProvider,
                                                 $providerKey)
    {
        return new DaoAuthenticationProvider($userProvider,
            $app['security.user_checker'], $providerKey,
            $this->encoderFactory ? : $app['security.encoder_factory']);
    }

    /**
     * {@inheritdoc}
     */
    public function getId()
    {
        return $this->id;
    }
}