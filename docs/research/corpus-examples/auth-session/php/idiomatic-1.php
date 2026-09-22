<?php
// Source: firebase/php-jwt, Authentication/JWT.php, commit b2c2be6a45fda769c8c2ffe5ec4259a9d1e46e5b
// ("Update decode() to require allowed algorithms arg when verifying") -- the fix for
// CVE-2015-2965, immediately after vulnerable-1.php's commit in the same file's history.
// License: BSD-3-Clause.
//
// Fix: decode() now takes $allowed_algs and actually enforces it -- `in_array($header->alg,
// $allowed_algs)` -- so a caller that only ever passes `['RS256']` will reject a forged
// token whose header claims `alg: HS256`, closing the algorithm/key-confusion hole.

/**
 * JSON Web Token implementation, based on this spec:
 * http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06
 *
 * PHP version 5
 *
 * @category Authentication
 * @package  Authentication_JWT
 * @author   Neuman Vong <neuman@twilio.com>
 * @author   Anant Narayanan <anant@php.net>
 * @license  http://opensource.org/licenses/BSD-3-Clause 3-clause BSD
 * @link     https://github.com/firebase/php-jwt
 */
class JWT
{
    public static $supported_algs = array(
        'HS256' => array('hash_hmac', 'SHA256'),
        'HS512' => array('hash_hmac', 'SHA512'),
        'HS384' => array('hash_hmac', 'SHA384'),
        'RS256' => array('openssl', 'SHA256'),
    );

    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string      $jwt           The JWT
     * @param string|Array|null $key     The secret key, or map of keys
     * @param Array       $allowed_algs  List of supported verification algorithms
     *
     * @return object      The JWT's payload as a PHP object
     *
     * @throws DomainException              Algorithm was not provided, or not allowed
     * @throws UnexpectedValueException     Provided JWT was invalid
     * @throws SignatureInvalidException    Provided JWT was invalid because the signature verification failed
     *
     * @uses jsonDecode
     * @uses urlsafeB64Decode
     */
    public static function decode($jwt, $key = null, $allowed_algs = array())
    {
        $tks = explode('.', $jwt);
        if (count($tks) != 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }
        list($headb64, $bodyb64, $cryptob64) = $tks;
        if (null === ($header = JWT::jsonDecode(JWT::urlsafeB64Decode($headb64)))) {
            throw new UnexpectedValueException('Invalid header encoding');
        }
        if (null === $payload = JWT::jsonDecode(JWT::urlsafeB64Decode($bodyb64))) {
            throw new UnexpectedValueException('Invalid claims encoding');
        }
        $sig = JWT::urlsafeB64Decode($cryptob64);
        if (isset($key)) {
            if (empty($header->alg)) {
                throw new DomainException('Empty algorithm');
            }
            if (empty(self::$supported_algs[$header->alg])) {
                throw new DomainException('Algorithm not supported');
            }
            // FIX: pin the token's algorithm against the caller's own allow-list, not
            // just against "is this a name we know how to implement".
            if (!is_array($allowed_algs) || !in_array($header->alg, $allowed_algs)) {
                throw new DomainException('Algorithm not allowed');
            }
            if (is_array($key)) {
                if (isset($header->kid)) {
                    $key = $key[$header->kid];
                } else {
                    throw new DomainException('"kid" empty, unable to lookup correct key');
                }
            }

            // Check the signature
            if (!JWT::verify("$headb64.$bodyb64", $sig, $key, $header->alg)) {
                throw new SignatureInvalidException('Signature verification failed');
            }
        }

        return $payload;
    }

    private static function verify($msg, $signature, $key, $alg)
    {
        if (empty(self::$supported_algs[$alg])) {
            throw new DomainException('Algorithm not supported');
        }

        list($function, $algorithm) = self::$supported_algs[$alg];
        switch ($function) {
            case 'openssl':
                $success = openssl_verify($msg, $signature, $key, $algorithm);
                if (!$success) {
                    throw new DomainException("OpenSSL unable to verify data: " . openssl_error_string());
                } else {
                    return $signature;
                }
            case 'hash_hmac':
            default:
                $hash = hash_hmac($algorithm, $msg, $key, true);
                if (function_exists('hash_equals')) {
                    return hash_equals($signature, $hash);
                }
                $len = min(self::safeStrlen($signature), self::safeStrlen($hash));
                $status = 0;
                for ($i = 0; $i < $len; $i++) {
                    $status |= (ord($signature[$i]) ^ ord($hash[$i]));
                }
                $status |= (self::safeStrlen($signature) ^ self::safeStrlen($hash));
                return ($status === 0);
        }
    }

    private static function safeStrlen($str)
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($str, '8bit');
        }
        return strlen($str);
    }
}
