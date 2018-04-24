<?php

namespace lukeelten\EncryptedSessionTest\Network;

use Cake\TestSuite\TestCase;

/**
 * Class RecaptchaComponentTest
 * @package lukeelten\EncryptedSessionTest\Network
 * @author Tobias Derksen <tobias@nulap.com>
 */
class EncryptedMiddlewareTest extends TestCase
{

    public function testCreation()
    {
        $instance = new EncryptedMiddlewareTest();

        $this->assertNotNull($instance);
    }
}
