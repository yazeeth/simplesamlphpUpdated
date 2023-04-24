<?php

declare(strict_types=1);

namespace SimpleSAML\Module\core\Auth\Source;

use SimpleSAML\Configuration;
use SimpleSAML\Error\Error;
use SimpleSAML\Utils\Crypto;
use Webmozart\Assert\Assert;

/**
 * Authentication source which verifies the password against
 * the 'auth.adminpassword' configuration option.
 *
 * @package SimpleSAMLphp
 */

class AdminPassword extends UserPassBase
{
    private const SESSION_PREFIX = 'adminpassword_';

    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct(array $info, array $config)
    {
        parent::__construct($info, $config);

        session_start();
        $this->setForcedUsername("admin");
    }

    /**
     * Attempt to log in using the given username and password.
     *
     * On a successful login, this function should return the users attributes. On failure,
     * it should throw an exception. If the error was caused by the user entering the wrong
     * username or password, a \SimpleSAML\Error\Error('WRONGUSERPASS') should be thrown.
     *
     * Note that both the username and the password are UTF-8 encoded.
     *
     * @param string $username  The username the user wrote.
     * @param string $password  The password the user wrote.
     * @return array  Associative array with the users attributes.
     */
    protected function login(string $username, string $password): array
    {
        $session_key = self::SESSION_PREFIX . session_id();

        if (!isset($_SESSION[$session_key])) {
            $_SESSION[$session_key] = [
                'wrongAttemptCount' => 0,
            ];
        }

        $config = Configuration::getInstance();
        $adminPassword = $config->getSecret('auth.adminpassword');
        if (empty($adminPassword)) {
            // We require that the user changes the password
            throw new Error\Error('NOTSET');
        }

        if ($username !== "admin") {
            throw new Error\Error('WRONGUSERPASS');
        }

        // Vulnerability modified by Yazeeth MS22038128
        // Use hash_equals() instead of Crypto::pwVerify() to prevent timing attacks
        if (!hash_equals(Crypto::generateHash($password), $adminPassword) || $_SESSION[$session_key]['wrongAttemptCount'] >= 5) {
            $_SESSION[$session_key]['wrongAttemptCount']++;
            throw new Error\Error('WRONGUSERPASS');
        }
        $_SESSION[$session_key]['wrongAttemptCount'] = 0;

        return ['user' => ['admin']];
    }
}
