<?php

namespace lukeelten\EncryptedSessionTest\Network\Session;

use Cake\TestSuite\TestCase;
use Cake\Utility\Security;
use lukeelten\EncryptedSession\Network\Session\EncryptedSession;

/**
 * Class EncryptedSessionTest
 * @package lukeelten\EncryptedSessionTest\Network\Session
 * @author Tobias Derksen <tobias@nulap.com>
 */
class EncryptedSessionTest extends TestCase
{
    const SALT = "SALT";

    protected $_key;
    protected $_instance;

    public function setUp()
    {
        parent::setUp();

        $key = Security::randomString(2048);
        $this->_key = Security::hash($key, "sha256");
    }

    public function testInvalidKey()
    {
        $mock = $this->createMock(\SessionHandlerInterface::class);
        $this->expectException(\InvalidArgumentException::class);

        new EncryptedSession("", null, $mock);
    }

    public function testCreation()
    {
        $mock = $this->createMock(\SessionHandlerInterface::class);
        $instance = new EncryptedSession($this->_key, null, $mock);
        $this->assertNotNull($instance);
    }

    public function testProxyMethods()
    {
        $mock = $this->createMock(\SessionHandlerInterface::class);

        $this->_instance = new EncryptedSession($this->_key, null, $mock);

        $return = Security::randomString();
        $mock->method("close")
            ->willReturn($return);

        $mock->method("destroy")
            ->willReturn($return);

        $mock->method("gc")
            ->willReturn($return);

        $mock->method("open")
            ->willReturn($return);

        $this->assertEquals($return, $this->_instance->close());
        $this->assertEquals($return, $this->_instance->destroy("test"));
        $this->assertEquals($return, $this->_instance->gc(10));
        $this->assertEquals($return, $this->_instance->open("test", "test"));
    }

    public function testEncryption()
    {
        $mock = $this->createMock(\SessionHandlerInterface::class);
        $mock->method("write")
            ->willReturnArgument(1);

        $this->_instance = new EncryptedSession($this->_key, self::SALT, $mock);

        $data = Security::randomString();
        $encrypted = $this->_instance->write("test", $data);
        $decrypted = Security::decrypt($encrypted, $this->_key, self::SALT);

        $this->assertEquals($data, $decrypted);
    }

    public function testDecryption()
    {
        $data = Security::randomString();
        $encrypted = Security::encrypt($data, $this->_key, self::SALT);

        $mock = $this->createMock(\SessionHandlerInterface::class);
        $mock->method("read")
            ->willReturn($encrypted);

        $this->_instance = new EncryptedSession($this->_key, self::SALT, $mock);
        $decrypted = $this->_instance->read("test");

        $this->assertEquals($data, $decrypted);
    }

    public function testEmptyRead()
    {
        $mock = $this->createMock(\SessionHandlerInterface::class);
        $mock->method("read")
            ->willReturn("");

        $this->_instance = new EncryptedSession($this->_key, self::SALT, $mock);
        $decrypted = $this->_instance->read("test");

        $this->assertEquals("", $decrypted);
    }

    public function testEmptyWrite()
    {
        $mock = $this->createMock(\SessionHandlerInterface::class);
        $mock->method("write")
            ->willReturnArgument(1);

        $this->_instance = new EncryptedSession($this->_key, self::SALT, $mock);
        $this->assertEquals("", $this->_instance->write("test", ""));
    }
}
