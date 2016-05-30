<?php

namespace Securilex;

class ServiceProvider extends \Silex\Provider\SecurityServiceProvider
{
    /**
     *
     * @var Firewall[]
     */
    protected $firewalls  = array();
    protected $registered = false;

    public function register(\Silex\Application $app)
    {
        parent::register($app);

        $firewallConfig = array();
        foreach ($this->firewalls as $firewall) {
            $firewall->register($app, $firewallConfig);
        }
        //var_dump($firewallConfig); exit;
        $app['security.firewalls'] = $firewallConfig;

        $this->registered = true;
    }

    public function addFirewall(Firewall $firewall)
    {
        $this->firewalls[$firewall->getName()] = $firewall;
    }
}