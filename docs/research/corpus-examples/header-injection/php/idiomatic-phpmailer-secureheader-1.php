<?php
// Excerpt of PHPMailer, src/PHPMailer.php (LGPL-2.1-only). Source: repo
// PHPMailer/PHPMailer, commit 50cd271fdf4e23673ded5455cdbaea007e05f619.
// This is the real fix-shape function PHPMailer added after historical
// header-injection CVEs (e.g. CVE-2016-10033/CVE-2017-5223 involved
// related sender-field injection issues).

/**
 * Strip newlines to prevent header injection.
 *
 * @param string $str
 *
 * @return string
 */
public function secureHeader($str)
{
    return trim(str_replace(["\r", "\n"], '', $str));
}
