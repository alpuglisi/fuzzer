<?php
// Excerpt combining two real files from the same plugin (see manifest.yaml
// for exact source paths/lines): the model's coupon-code lookup/decrement
// methods, and the controller flow that redeems a code. Trimmed to the
// single reward branch (code_type 1-3, currency reward) that most clearly
// shows the check-then-act race; the plugin.php original has ~8 near-
// identical branches (zen, ruud, items, vip, ...) all following the same
// checkCode() -> [validation] -> setUsesLeft() shape.

// ---- application/plugins/gift_code/models/model.gift_code.php ----
class Mgift_code extends model
{
    // Reads the coupon row, including its remaining-uses counter.
    public function checkCode($code){
        return $this->website->db('web')->query('SELECT id, code, expires, max_uses_total, uses_left, max_uses_by_user, max_uses_by_char, min_lvl, min_mlvl, min_res, min_gres, code_type, code_reward_currency, code_reward_vip, code_reward_items, char_class, server FROM DmN_Gift_Codes WHERE code = \''.$this->website->db('web')->sanitize_var($code).'\'')->fetch();
    }

    public function checkUsesByAccount($coupon, $user, $server){
        return $this->website->db('web')->snumrows('SELECT COUNT(id) AS count FROM DmN_Gift_Codes_Log WHERE code = \''.$this->website->db('web')->sanitize_var($coupon).'\' AND account = \''.$this->website->db('web')->sanitize_var($user).'\' AND server = \''.$this->website->db('web')->sanitize_var($server).'\'');
    }

    public function logGiftCode($code, $character, $user, $server){
        $stmt = $this->website->db('web')->prepare('INSERT INTO DmN_Gift_Codes_Log (code, account, server, character, date_used) VALUES (:code, :account, :server, :character, :date_used)');
        $stmt->execute([
            ':code' => $code,
            ':account' => $user,
            ':server' => $server,
            ':character' => $character,
            ':date_used' => time()
        ]);
    }

    // Unconditional decrement -- no "WHERE uses_left > 0" guard, no row
    // lock, no transaction wrapping the earlier checkCode() read. This is
    // the second half of the check-then-act race: any number of concurrent
    // requests that already passed the uses_left <= 0 check in plugin.php
    // will each run this UPDATE, so uses_left can be driven well past what
    // max_uses_total should have allowed.
    public function setUsesLeft($coupon){
        $this->website->db('web')->query('UPDATE DmN_Gift_Codes SET uses_left = uses_left - 1 WHERE  code = \''.$this->website->db('web')->sanitize_var($coupon).'\'');
    }
}

// ---- application/plugins/gift_code/plugin.php (redeem_coupon handler) ----
// (method body inlined for a single controller class in the original file)

if (isset($_POST['redeem_coupon'])) {
    $coupon = isset($_POST['coupon']) ? $_POST['coupon'] : '';
    $character = isset($_POST['character']) ? $_POST['character'] : '';

    // --- CHECK: read the coupon row and its uses_left counter ---
    $this->vars['coupon_data'] = $this->pluginaizer->Mgift_code->checkCode($coupon);
    if ($this->vars['coupon_data'] != false) {
        if ($this->vars['coupon_data']['uses_left'] <= 0) {
            $this->vars['error'] = __('Coupon has reached max uses.');
        } else {
            // ... (server check, expiry check, per-account/per-character
            // usage-cap checks, min-level checks all elided here -- none
            // of them re-read or lock uses_left; they only add more
            // wall-clock time between the check above and the act below,
            // widening the race window)
            $this->vars['use_count_acc'] = $this->pluginaizer->Mgift_code->checkUsesByAccount(
                $coupon,
                $this->pluginaizer->session->userdata(['user' => 'username']),
                $this->pluginaizer->session->userdata(['user' => 'server'])
            );

            switch ($this->vars['coupon_data']['code_type']) {
                case 1:
                case 2:
                case 3:
                    $this->pluginaizer->website->add_credits(
                        $this->pluginaizer->session->userdata(['user' => 'username']),
                        $this->pluginaizer->session->userdata(['user' => 'server']),
                        $this->vars['coupon_data']['code_reward_currency'],
                        $this->vars['coupon_data']['code_type'],
                        false,
                        $this->pluginaizer->Mgift_code->get_guid(
                            $this->pluginaizer->session->userdata(['user' => 'username']),
                            $this->pluginaizer->session->userdata(['user' => 'server'])
                        )
                    );
                    $this->pluginaizer->Mgift_code->logGiftCode(
                        $coupon, $character,
                        $this->pluginaizer->session->userdata(['user' => 'username']),
                        $this->pluginaizer->session->userdata(['user' => 'server'])
                    );
                    // --- ACT: decrement uses_left, far downstream and in
                    // a wholly separate statement/request from the check
                    // above, with no lock held across the two ---
                    $this->pluginaizer->Mgift_code->setUsesLeft($coupon);
                    $this->vars['success'] = __('Gift code activated successfully.');
                    break;
            }
        }
    }
}
