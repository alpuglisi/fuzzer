<?php
// Source: InvoicePlane/InvoicePlane, application/modules/sessions/controllers/Sessions.php,
// commit a479033943de0de61b62743fd6abb6d277b69f2d (the commit immediately BEFORE the
// aeddda43... fix below, in the same file's history). License: MIT (code); the
// "InvoicePlane" name/logo carry a separate trademark restriction that does not apply to
// this source excerpt (see the repo's LICENSE.txt).
//
// Excerpt from Sessions::forgotPassword(), CodeIgniter 3 controller. Trimmed to the
// token-generation step and its surrounding control flow; the full method also does bot
// detection and IP/email rate limiting (omitted here as unrelated to the token weakness).
//
// Vulnerability (CWE-330 predictable value / CVE-2021-29023): the reset token is
// md5(time() . $email . $this->crypt->salt()). $email is known to the attacker (it's the
// address they're attacking) and time() is a low-entropy, narrow-window value guessable to
// within seconds from the HTTP response's own Date header -- so the only real secret input
// is $this->crypt->salt(), and the *comment* claims that salt exists specifically "to
// prevent predictability" (CVE-2021-29023). MD5 of a mostly-known/guessable input, rather
// than a token drawn from a CSPRNG, remains brute-forceable within the small remaining
// keyspace once email+time are pinned down.

class Sessions extends Base_Controller
{
    public function forgotPassword()
    {
        // ... email validation, bot detection, and rate-limit checks omitted ...

        $email = $this->input->post('email', true);

        // Test if a user with this email exists
        $this->db->where('user_email', $email);
        $user = $this->db->get('ip_users')->row();

        // Security: Always show the same message regardless of whether email exists
        // This prevents email enumeration attacks
        if ($user) {
            // User exists - send actual reset email
            //use salt to prevent predictability of the reset token (CVE-2021-29023)
            $this->load->library('crypt');
            $token = md5(time() . $email . $this->crypt->salt());

            // Save the token to the database
            $db_array = [
                'user_passwordreset_token' => $token,
            ];

            $this->db->where('user_email', $email);
            $this->db->update('ip_users', $db_array);

            // Send the email with reset link
            $this->load->helper('mailer');
            $email_resetlink = site_url('sessions/passwordreset/' . $token);
            $email_message   = $this->load->view('emails/passwordreset', [
                'resetlink' => $email_resetlink,
            ], true);

            // ... mail-sending branch omitted ...
        }

        // ... generic "check your email" response omitted ...
    }
}
