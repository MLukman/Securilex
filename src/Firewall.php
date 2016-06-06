<?php

namespace Securilex;

use Securilex\Authentication\AuthenticationFactoryInterface;
use Symfony\Component\Security\Core\User\ChainUserProvider;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\EntryPoint\BasicAuthenticationEntryPoint;
use Symfony\Component\Security\Http\EntryPoint\FormAuthenticationEntryPoint;
use Symfony\Component\Security\Http\Firewall\ContextListener;

class Firewall
{
    protected $path          = null;
    protected $drivers       = array();
    protected $userProviders = array();
    protected $authFactories = array();
    protected $loginpath     = null;
    protected $logincheck    = null;
    protected $name          = null;

    /**
     *
     * @var ServiceProvider
     */
    protected $provider = null;

    public function __construct($path,
                                AuthenticationFactoryInterface $authFactory,
                                UserProviderInterface $userProvider,
                                $loginpath = null, $logincheck = null)
    {
        if (substr($path, -1) != '/') {
            $path .= '/';
        }
        $this->path       = $path;
        $this->loginpath  = $loginpath;
        $this->logincheck = $logincheck;
        $this->name       = md5($this->path);
        $this->addAuthenticationFactory($authFactory, $userProvider);
    }

    public function getPath()
    {
        return $this->path;
    }

    public function addAuthenticationFactory(AuthenticationFactoryInterface $authFactory,
                                             UserProviderInterface $userProvider)
    {
        $id = $authFactory->getId();

        $this->authFactories[$id] = array(
            'factory' => $authFactory,
            'userProvider' => $userProvider,
        );

        $this->userProviders[] = $userProvider;

        if ($this->provider) {
            $this->registerAuthenticationFactory($this->provider->getApp(), $id,
                $authFactory, $userProvider);
        }
    }

    /**
     * Register the Firewall
     * @param ServiceProvider $provider Service Provider
     */
    public function register(ServiceProvider $provider)
    {
        $this->provider = $provider;

        if ($this->loginpath) {
            $this->provider->prependFirewallConfig("{$this->name}_login",
                array('pattern' => "^{$this->loginpath}$"));
        }

        $config = array('logout' => true);

        $app = $this->provider->getApp();
        foreach ($this->authFactories as $id => $authFactory) {
            $this->registerAuthenticationFactory($app, $id,
                $authFactory['factory'], $authFactory['userProvider']);
            $config[$id] = array();
            if ($this->loginpath) {
                $config[$id]['login_path'] = $this->loginpath;
                $config[$id]['check_path'] = $this->logincheck;
            }
        }

        $this->registerUserProvider($app);
        $this->registerContextListener($app);
        $this->registerEntryPoint($app);

        $this->provider->appendFirewallConfig($this->name, $config);
    }

    protected function registerAuthenticationFactory(\Silex\Application $app,
                                                     $id,
                                                     AuthenticationFactoryInterface $authFactory,
                                                     UserProviderInterface $userProvider)
    {
        $fac = 'security.authentication_listener.factory.'.$id;
        if (isset($app[$fac])) {
            return;
        }

        $app[$fac] = $app->protect(function ($name, $options) use ($app, $id, $authFactory, $userProvider) {
            // the authentication type
            $type        = (isset($options['login_path']) ? 'form' : 'http');
            $entry_point = "security.entry_point.$name.$type";

            // the authentication provider id
            $auth_provider       = "security.authentication_provider.$name.$id";
            $app[$auth_provider] = $app->share(function () use ($app, $name, $authFactory, $userProvider) {
                return $authFactory->createAuthenticationProvider($app,
                        $userProvider, $name);
            });

            // the authentication listener id
            $auth_listener       = "security.authentication_listener.$name.$id";
            $app[$auth_listener] = $app["security.authentication_listener.$type._proto"]($name,
                $options);

            return array($auth_provider, $auth_listener, $entry_point, 'pre_auth');
        });
    }

    /**
     * Register User Provider
     * @param \Silex\Application $app
     */
    protected function registerUserProvider(\Silex\Application $app)
    {
        $user_provider       = 'security.user_provider.'.$this->name;
        $app[$user_provider] = $app->share(function () {
            return new ChainUserProvider($this->userProviders);
        });
        return $user_provider;
    }

    /**
     * Register Context Listener
     * @param \Silex\Application $app
     */
    protected function registerContextListener(\Silex\Application $app)
    {
        $context_listener       = 'security.context_listener.'.$this->name;
        $app[$context_listener] = $app->share(function () use ($app) {
            return new ContextListener(
                $app['security.token_storage'], $this->userProviders,
                $this->name, $app['logger'], $app['dispatcher']
            );
        });
        return $context_listener;
    }

    /**
     * Register Entry Point
     * @param \Silex\Application $app
     */
    protected function registerEntryPoint(\Silex\Application $app)
    {
        $entry_point       = 'security.entry_point.'.$this->name.
            (empty($this->loginpath) ? '.http' : '.form');
        $app[$entry_point] = $app->share(function () use ($app) {
            return $this->loginpath ?
                new FormAuthenticationEntryPoint($app,
                $app['security.http_utils'], $this->loginpath, false) :
                new BasicAuthenticationEntryPoint('Secured');
        });
        return $entry_point;
    }
}