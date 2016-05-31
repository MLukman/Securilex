<?php

namespace Securilex;

class ServiceProvider extends \Silex\Provider\SecurityServiceProvider
{
    /**
     *
     * @var Firewall[]
     */
    protected $firewalls = array();

    /**
     *
     * @var \Silex\Application
     */
    protected $app = null;

    /**
     *
     * @var array
     */
    protected $firewallConfig = array();

    public function register(\Silex\Application $app)
    {
        parent::register($app);
        $this->app = $app;

        foreach ($this->firewalls as $firewall) {
            $firewall->register($this);
        }
        $this->refreshFirewallConfig();
    }

    /**
     * Add Firewall
     * @param \Securilex\Firewall $firewall
     */
    public function addFirewall(Firewall $firewall)
    {
        $this->firewalls[$firewall->getPath()] = $firewall;

        if ($this->app) {
            $firewall->register($this->app, $this->firewallConfig);
            $this->refreshFirewallConfig();
        }
    }

    /**
     * Get Firewall with the specific path
     * @param string $path
     * @return Firewall
     */
    public function getFirewall($path)
    {
        return (isset($this->firewalls[$path]) ? $this->firewalls[$path] : null);
    }

    /**
     * Get the Application
     * @return \Silex\Application
     */
    public function getApp()
    {
        return $this->app;
    }

    public function prependFirewallConfig($name, $config)
    {
        $this->firewallConfig = array_merge(
            array($name => $config), $this->firewallConfig);
    }

    public function appendFirewallConfig($name, $config)
    {
        $this->firewallConfig[$name] = $config;
    }

    public function refreshFirewallConfig()
    {
        if ($this->app) {
            $this->app['security.firewalls'] = $this->firewallConfig;
        }
    }
}