<?php

namespace lukeelten\EncryptedSession\Network\Session;


use Cake\Utility\Security;

/**
 * Class which can be registered as a session engine and decrypts data when session is read and encrypts data when session is written.
 *
 * @package lukeelten\EncryptedSession\Network\Session
 * @author Tobias Derksen <tobias@nulap.com>
 */
class EncryptedSession implements \SessionHandlerInterface {

    /**
     * @var string
     */
    protected $_key;

    /**
     * Server-side salt to use for de- and encryption.
     * Using a server-side salt increases security so the real encryption key is not stored at one place.
     *
     * @var string|null
     */
    protected $_salt;

    /**
     * Original Session Engine
     * @var \SessionHandlerInterface
     */
    protected $_engine;

    /**
     * EncryptedSession constructor.
     *
     * @param string $key Encryption key to use for this session
     * @param string|null $salt Service-side salt. If null, Security.Salt will be used.
     * @param \SessionHandlerInterface $engine Original session engine
     */
    public function __construct(string $key, ?string $salt, \SessionHandlerInterface $engine) {
        $this->_key = $key;
        $this->_salt = $salt;
        $this->_engine = $engine;

        if (empty($this->_key)) {
            throw new \InvalidArgumentException("Empty encryption key given to EncryptedSession");
        }

        if (empty($this->_engine)) {
            throw new \InvalidArgumentException("No session engine found. Please configure a session engine before using EncryptedSession.");
        }
    }

    /**
     * Method proxies call to original session engine
     *
     * {@inheritdoc }
     */
    public function close() {
        return $this->_engine->close();
    }

    /**
     * Method proxies call to original session engine
     *
     * {@inheritdoc }
     */
    public function destroy($session_id) {
        return $this->_engine->destroy($session_id);
    }

    /**
     * Method proxies call to original session engine
     *
     * {@inheritdoc }
     */
    public function gc($maxlifetime) {
        return $this->_engine->gc($maxlifetime);
    }

    /**
     * Method proxies call to original session engine
     *
     * {@inheritdoc }
     */
    public function open($save_path, $name) {
        return $this->_engine->open($save_path, $name);
    }

    /**
     * Reads session from original session engine and decrypts the data.
     *
     * {@inheritdoc }
     */
    public function read($session_id) {
        $data = $this->_engine->read($session_id);

        if (!empty($data)) {
            $decrypted = Security::decrypt($data, $this->_key, $this->_salt);
            if (!empty($decrypted)) {
                return $decrypted;
            }
        }

        return '';
    }

    /**
     * Encrypts session data with a per-user key and forward the encrypted data to the original session engine
     *
     * {@inheritdoc }
     */
    public function write($session_id, $data) {
        if (!empty($data)) {
            $data = Security::encrypt($data, $this->_key, $this->_salt);
        }

        return $this->_engine->write($session_id, $data);
    }
}