<?php
// Source: InvoicePlane/InvoicePlane, application/helpers/security_helper.php (new file) +
// application/modules/sessions/controllers/Sessions.php (updated caller), commit
// aeddda4397395eb63b2636554976add2611ad0a8 ("Replace weak PRNG with cryptographically
// secure random_bytes() for token generation", fixing CVE-2021-29023 -- the direct
// successor commit to vulnerable-2.php's state in the same file's history).
// License: MIT.
//
// Fix: the reset token is now 32 bytes (256 bits) from random_bytes(), a CSPRNG, instead
// of md5() over mostly-attacker-known inputs (email, time()) plus a salt. The token no
// longer depends on any guessable input at all.

if (!defined('BASEPATH')) {
    exit('No direct script access allowed');
}

/**
 * Security Helper.
 *
 * Provides cryptographically secure functions for token generation, password reset tokens,
 * and other security-critical operations.
 */

/**
 * Generate a cryptographically secure random token.
 *
 * Uses PHP's random_bytes() with fallback to paragonie/random_compat for older PHP versions.
 * Provides 128+ bits of entropy for security-critical operations like password resets.
 *
 * @param int $length The length of the raw token in bytes (default: 32 bytes = 256 bits)
 *
 * @return string The token as a hexadecimal string (twice the byte length)
 */
function generate_secure_token(int $length = 32): string
{
    try {
        // Generate cryptographically secure random bytes
        $randomBytes = random_bytes($length);

        // Convert to hexadecimal for safe storage and transmission
        return bin2hex($randomBytes);
    } catch (Exception $e) {
        // This should never happen with PHP 7.0+ or random_compat library
        log_message('error', 'Failed to generate secure random token: ' . $e->getMessage());
        throw new RuntimeException('Unable to generate secure random token');
    }
}

/**
 * Generate a cryptographically secure password reset token.
 *
 * Creates a token with 256 bits of entropy (32 bytes), suitable for password reset operations.
 * This replaces the previous insecure implementation that used md5(time() + email + mt_rand()).
 *
 * @return string A 64-character hexadecimal token
 */
function generate_password_reset_token(): string
{
    // Generate 32 bytes (256 bits) of entropy
    // This provides sufficient security against brute force attacks
    return generate_secure_token(32);
}

// --- caller, excerpted from Sessions::forgotPassword() ---
//
// if ($user) {
//     // User exists - send actual reset email
//     // Use cryptographically secure token generation (fixes CVE-2021-29023)
//     $this->load->helper('security');
//     $token = generate_password_reset_token();
//
//     // Save the token to the database
//     $db_array = [
//         'user_passwordreset_token' => $token,
//     ];
//     $this->db->where('user_email', $email);
//     $this->db->update('ip_users', $db_array);
// }
