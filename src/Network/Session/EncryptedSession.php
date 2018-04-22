<?php

namespace lukeelten\EncryptedSession\Network\Session;


use Cake\Utility\Security;

/**
 * Class EncryptedSession
 * @package lukeelten\EncryptedSession\Network\Session
 * @author Tobias Derksen <tobias@nulap.com>
 */
class EncryptedSession implements \SessionHandlerInterface {

    /**
     * @var string
     */
    protected $_key;

    /**
     * @var string|null
     */
    protected $_salt;

    /**
     * @var \SessionHandlerInterface
     */
    protected $_engine;

    /**
     * EncryptedSession constructor.
     * @param string $key
     * @param string $salt
     * @param \SessionHandlerInterface $engine
     */
    public function __construct(string $key, ?string $salt, \SessionHandlerInterface $engine) {
        $this->_key = $key;
        $this->_salt = $salt;
        $this->_engine = $engine;
    }

    /**
     * {@inheritdoc }
     */
    public function close() {
        return $this->_engine->close();
    }

    /**
     * {@inheritdoc }
     */
    public function destroy($session_id) {
        return $this->_engine->destroy($session_id);
    }

    /**
     * {@inheritdoc }
     */
    public function gc($maxlifetime) {
        return $this->_engine->gc($maxlifetime);
    }

    /**
     * {@inheritdoc }
     */
    public function open($save_path, $name) {
        return $this->_engine->open($save_path, $name);
    }

    /**
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
     * {@inheritdoc }
     */
    public function write($session_id, $data) {
        if (!empty($data)) {
            $data = Security::encrypt($data, $this->_key, $this->_salt);
        }

        return $this->_engine->write($session_id, $data);
    }
}