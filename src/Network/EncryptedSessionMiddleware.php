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
class EncryptedSessionMiddleware {

    const COOKIE_KEY = "NULAP_COOKIE";

    /**
     * @var array
     */
    protected $_options;

    public function __construct(array $options = []) {
        $this->_options += $options + [
            "salt" => Configure::read("Session.key") ,
            "cookieName" => ""
        ];
    }

    /**
     * Invoke middleware
     *
     * @param ServerRequest $request
     * @param Response $response
     * @param callable $next
     * @return Response
     */
    public function __invoke(ServerRequest $request, Response $response, $next) {
        $cookies = $request->getCookieParams();

        if (!empty($cookies[self::COOKIE_KEY])) {
            $key = $cookies[self::COOKIE_KEY];
        } else {
            $key = $this->_generateKey();
        }

        $oldEngine = $request->getSession()->engine();
        $engine = new EncryptedSession($key, $this->_options["salt"], $oldEngine);

        // Register self as session handler
        $request->getSession()->engine($engine);

        /**
         * @var $response Response
         */
        $response = $next($request, $response);

        return $response->withCookie(self::COOKIE_KEY, [
            'value' => $key,
            'path' => '/',
            'httpOnly' => false,
            'secure' => false,
            'expire' => strtotime('+1 year')
        ]);
    }

    /**
     * Generate new random key
     *
     * @return string
     */
    private function _generateKey() : string {
        $random = Security::randomBytes(2048);
        $random .= Security::insecureRandomBytes(2048);
        return Security::hash($random, "sha256");
    }

}