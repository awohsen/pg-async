<?php

namespace PgAsync\Message;

class Authentication extends Message
{
    const AUTH_OK = 0; // AuthenticationOk
    const AUTH_KERBEROS_V_5 = 2; // AuthenticationKerberosV5
    const AUTH_CLEARTEXT_PASSWORD = 3; // AuthenticationCleartextPassword
    const AUTH_MD5_PASSWORD = 5; // AuthenticationMD5Password
    const AUTH_SCM_CREDENTIAL = 6; // AuthenticationSCMCredential
    const AUTH_GSS = 7; // AuthenticationGSS
    const AUTH_GSS_CONTINUE = 8; // AuthenticationGSSContinue
    const AUTH_SSPI = 9; // AuthenticationSSPI

    const AUTH_SASL = 10; // AuthenticationSASLPassword

    private $authCode;

    private $salt;

    /**
     * @inheritDoc
     * @throws \InvalidArgumentException
     */
    public function parseMessage(string $rawMessage)
    {
        $authCode = unpack("N", substr($rawMessage, 5, 4))[1];
        switch ($authCode) {
            case $this::AUTH_OK:
                break; // AuthenticationOk
            case $this::AUTH_KERBEROS_V_5:
                break; // AuthenticationKerberosV5
            case $this::AUTH_CLEARTEXT_PASSWORD:
                break; // AuthenticationCleartextPassword
            case $this::AUTH_MD5_PASSWORD:
                if (strlen($rawMessage) !== 13) {
                    throw new \InvalidArgumentException('Invalid raw message length for MD5 authentication message.');
                }

                $this->salt = substr($rawMessage, 9, 4);

                break; // AuthenticationMD5Password
            case $this::AUTH_SCM_CREDENTIAL:
                break; // AuthenticationSCMCredential
            case $this::AUTH_GSS:
                break; // AuthenticationGSS
            case $this::AUTH_GSS_CONTINUE:
                break; // AuthenticationGSSContinue
            case $this::AUTH_SSPI:
                break; // AuthenticationSSPI
            case $this::AUTH_SASL:
                // todo implement scram-sha-256
                break;
        }

        $this->authCode = $authCode;
    }

    public static function getMessageIdentifier(): string
    {
        return 'R';
    }

    public function getAuthCode(): int
    {
        return $this->authCode;
    }

    public function getSalt(): string
    {
        if ($this->getAuthCode() === $this::AUTH_MD5_PASSWORD ||
            $this->getAuthCode() === $this::AUTH_SASL
        ) {
            return $this->salt;
        }

        throw new \Exception('getSalt called on non-md5 authentication message');
    }
}
