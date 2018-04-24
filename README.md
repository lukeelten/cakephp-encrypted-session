# CakePHP Session Encryption

This is a CakePHP Plugin which encrypts a user's session data transparently before storing it.
The session data will be automatically decrypted during the next request.

## Why do I need this?
The new GDPR regulation does not enforce encryption on personal data, 
nevertheless it is recommended to encrypt personal data everywhere, especially at rest.
A saved session is simply data stored at rest.

Due to user authorization or other application features, the session often contains data which can be
classified as personal data according to the GDPR. Therefore encrypting them is a reasonable safety measure to 
prevent data breaches.

To increase security, a unique encryption key is generated for each user and stored into a cookie. 
Keeping the key away from the server, makes decrypting all of the session data at once a very hard task.


## Installation

Install plugin using [composer](http://getcomposer.org):
```php
composer require lukeelten/cakephp-encrypted-session
```

The plugin does not need any loading during bootstrap.

## Configuration
There are several options to configure the behavior, nevertheless the plugin contains a useful set of default
values, so you __do not need any configuration at all__.

Nevertheless, it is recommended to configure at least a encryption salt, otherwise Security.salt will be used.

Possible options to add to application config:
```php
'Session' => [
    "Encryption" => [
        "salt" => getenv("SESSION_SALT", "default-salt"), // Server side salt; fill in random string
        "cookieName" => "CAKE_SESSION_KEY", // Cookie name
        "expire" => strtotime("+1 year"), // Default cookie lifetime
        "secure" => false, // Use with https only
        "path" => "/" // Cookie path
    ]
]
```

## Usage

Simply add the middleware to your Application middleware setup (Application.php)
```php
$middleware->add(new EncryptedSessionMiddleware());
```

### Important Note:
If this middleware is used in combination with "EncryptedCookieMiddleware" and you want to encrypt the session key cookie 
as well, you must ensure, that the "EncryptedCookieMiddleware" is loaded into the middleware chain BEFORE the
"EncryptedSessionMiddleware".

```php
$middleware->add(new EncryptedCookieMiddleware())
    ->add(new EncryptedSessionMiddleware());
```