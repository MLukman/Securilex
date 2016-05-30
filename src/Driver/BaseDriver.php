<?php

namespace Securilex\Driver;

abstract class BaseDriver implements \Securilex\DriverInterface
{

    /**
     * {@inheritdoc}
     */
    public function getBuiltInUserProvider()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function register(\Silex\Application $app)
    {
        $id  = $this->getId();
        $fac = 'security.authentication_listener.factory.'.$id;
        if (isset($app[$fac])) {
            return;
        }

        $app[$fac] = $app->protect(function ($name, $options) use ($app, $id) {
            // the authentication type
            $type        = (isset($options['login_path']) ? 'form' : 'http');
            $entry_point = "security.entry_point.$name.$type";

            // the authentication provider id
            $auth_provider       = "security.authentication_provider.$name.$id";
            $app[$auth_provider] = $app->share(function () use ($app, $name) {
                return $this->getAuthenticationProvider($app, $name);
            });

            // the authentication listener id
            $auth_listener       = "security.authentication_listener.$name.$id";
            $app[$auth_listener] = $app["security.authentication_listener.$type._proto"]($name,
                $options);

            return array($auth_provider, $auth_listener, $entry_point, 'pre_auth');
        });
    }
}