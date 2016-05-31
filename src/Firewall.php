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
    protected $logincheck    = null;
    protected $name          = null;

    /**
     *
     * @var ServiceProvider
     */
    protected $provider = null;

    public function __construct($path, DriverInterface $driver,
                                $loginpath = null, $logincheck = null)
    {
        if (substr($path, -1) != '/') {
            $path .= '/';
        }
        $this->path       = $path;
        $this->loginpath  = $loginpath;
        $this->logincheck = $logincheck;
        $this->name       = md5($this->path);
        $this->addDriver($driver);
    }

    public function getPath()
    {
        return $this->path;
    }

    public function addDriver(DriverInterface $driver)
    {
        $this->drivers[(string) $driver->getId()] = $driver;

        if (($userProvider = $driver->getBuiltInUserProvider())) {
            $this->addUserProvider($userProvider);
        }

        if ($this->provider) {
            $driver->register($this->provider->getApp());
        }
    }

    public function addUserProvider(UserProviderInterface $userProvider)
    {
        $this->userProviders[] = $userProvider;
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

        $config = array(
            'logout' => true,
        );

        $app = $this->provider->getApp();
        foreach ($this->drivers as $driver) {
            $driver->register($app);
            if ($this->loginpath) {
                $config[$driver->getId()] = array(
                    'login_path' => $this->loginpath,
                    'check_path' => $this->logincheck,
                );
            } else {
                $config[$driver->getId()] = array();
            }
        }

        $this->registerUserProvider($app);
        $this->registerContextListener($app);
        $this->registerEntryPoint($app);

        $this->provider->appendFirewallConfig($this->name, $config);
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