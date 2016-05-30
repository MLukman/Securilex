<?php

namespace Securilex;

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
    protected $loginpath     = null;
    protected $name          = null;

    public function __construct($path, DriverInterface $driver,
                                $loginpath = null)
    {
        if (substr($path, -1) != '/') {
            $path .= '/';
        }
        $this->path      = $path;
        $this->loginpath = $loginpath;
        $this->name      = $this->path;
        $this->addDriver($driver);
    }

    public function addDriver(DriverInterface $driver)
    {
        $this->drivers[(string) $driver->getId()] = $driver;

        if (($userProvider = $driver->getBuiltInUserProvider())) {
            $this->addUserProvider($userProvider);
        }
    }

    public function addUserProvider(UserProviderInterface $userProvider)
    {
        $this->userProviders[] = $userProvider;
    }

    public function getName()
    {
        return $this->name;
    }

    /**
     * Register the Firewall
     * @param \Silex\Application $app
     */
    public function register(\Silex\Application $app, array &$firewallConfig)
    {
        $config = array(
            'logout' => true,
        );

        foreach ($this->drivers as $driver) {
            $driver->register($app);
            if ($this->loginpath) {
                $config[$driver->getId()] = array(
                    'login_path' => $this->loginpath,
                    'check_path' => $this->loginpath.'/doLogin',
                );
            } else {
                $config[$driver->getId()] = array();
            }
        }

        $this->registerUserProvider($app);
        $this->registerContextListener($app);
        $this->registerEntryPoint($app);

        if ($this->loginpath) {
            $firewallConfig = array_merge(
                array("{$this->name}_login" => array('pattern' => "^{$this->loginpath}$")),
                $firewallConfig);
        }

        $firewallConfig[$this->name] = $config;
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