<?php

namespace lukeelten\EncryptedSession\Network;

use Cake\Core\Configure;
use Cake\Http\Response;
use Cake\Http\ServerRequest;
use Cake\Utility\Security;
use lukeelten\EncryptedSession\Network\Session\EncryptedSession;

/**
 * Class EncryptedSessionMiddleware
 *
 * Middleware encrypts user session with a unique encryption key for each user.
 * The session is encrypted using AES-256.
 * The encryption key is stored in a cookie.
 *
 * IMPORTANT:
 * If used along with EncryptedCookieMiddleware and the cookie which holds the encryption key is encrypted,
 * the EncryptedCookieMiddleware must be loaded BEFORE this middleware. Ensure this by using proper priorities.
 *
 * @package Nulap\Library
 * @author Tobias Derksen <tobias@nulap.com>
 */
class EncryptedSessionMiddleware
{

    /**
     * @var array
     */
    protected $_options;

    /**
     * EncryptedSessionMiddleware constructor.
     *
     * ### Options
     * - `salt`: server-side encryption salt
     * - `cookieName`: Name of the cookie
     * - `expire`: Time the cookie expires in
     * - `path`: Path the cookie applies to
     * - `secure`: Is the cookie https?
     * - `httpOnly`: Is the cookie available in the client?
     *
     * @param array $options Middleware options
     */
    public function __construct(array $options = [])
    {
        $config = Configure::read("Session.Encryption", []);

        // Enforce default options
        $this->_options += $options + $config + [
            "salt" => null,
            "cookieName" => "CAKE_SESSION_KEY",
            "httpOnly" => true,
            "expire" => Configure::read("Session.timeout") ?? strtotime("+1 year"),
            "secure" => false,
            "path" => "/"
        ];
    }

    /**
     * Invoke middleware
     * Middleware handles encryption key and instantiate an EncryptedSession object which takes care of transparent session encryption.
     *
     * @param ServerRequest $request Request object
     * @param Response $response Response object
     * @param callable $next Next middleware in chain
     * @return Response Modified response object
     */
    public function __invoke(ServerRequest $request, Response $response, $next)
    {
        $cookies = $request->getCookieParams();

        if (!empty($cookies[$this->_options["cookieName"]])) {
            $key = $cookies[$this->_options["cookieName"]];
        } else {
            $key = $this->_generateKey();
        }

        $oldEngine = $request->getSession()->engine();
        $engine = new EncryptedSession($key, $this->_options["salt"], $oldEngine);

        // Register self as session handler
        $request->getSession()->engine($engine);
        $response = $next($request, $response);

        return $response->withCookie($this->_options["cookieName"], [
            'value' => $key,
            'path' => $this->_options["path"],
            'httpOnly' => $this->_options["httpOnly"],
            'secure' => $this->_options["secure"],
            'expire' => $this->_options["expire"]
        ]);
    }

    /**
     * Generate new random key
     * Uses combination of secure and insecure random bytes and generates a 256bit key.
     *
     * @return string Generated key
     */
    private function _generateKey() : string
    {
        $random = Security::randomBytes(2048);
        $random .= Security::insecureRandomBytes(2048);

        return Security::hash($random, "sha256");
    }
}
