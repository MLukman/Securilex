<?php

namespace Securilex\Authorization;

interface SecuredAccessInterface
{

    /**
     * Allow user role to access
     * @param string $role User role to allow access
     * @return self $this object (to allow method chaining)
     */
    public function addAllowedRole($role);

    /**
     * Check if a specific user role is allowed to access
     * @param string $role User role
     * @return bool
     */
    public function isRoleAllowed($role);

    /**
     * Allow username to access
     * @param string $username Username to allow access
     * @return self $this object (to allow method chaining)
     */
    public function addAllowedUsername($username);

    /**
     * Check if a specific username is allowed to access this context
     * @param string $username Username
     * @return bool
     */
    public function isUsernameAllowed($username);

    /**
     * Check if current user/instance has access to this object
     * @param \Silex\Application $app The application instance to evaluate on
     * @return boolean if current user has access
     */
    public function checkAccess(\Silex\Application $app);
}