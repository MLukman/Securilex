# Securilex
Securilex is a simplified security provider for Silex.

The main class for Securilex is `\Securilex\ServiceProvider`.

Usage:

	// $app is instance of \Silex\Application
	$app->register(new \Securilex\ServiceProvider());

    // securilex is now a service
    $app['securilex']-> ...

## Authentication
Authentication deals with identifying user identity via login mechanism. The main class for authentication is `\Securilex\Firewall`.

To define a firewall, you need to define four items:

1. **The path to secure**: whether the whole site (/) or just specific area (/admin/).
2. **The user provider** = source to get the list of users, e.g. hard-coded, database etc.
3. **The authentication factory** = method of authentication, e.g. plaintext password validation, encoded password validation, LDAP, OAuth etc.
4. **The path to login page** = optional, if none specific it will use browser login popup (i.e. Basic HTTP Authentication).

Register the firewall to securilex using `addFirewall()` method:

	$app['securilex']->addFirewall(new \Securilex\Firewall(...));

## Authorization
Authorization deals with allowing or denying access to page or resource.

// TODO: Work In Progress