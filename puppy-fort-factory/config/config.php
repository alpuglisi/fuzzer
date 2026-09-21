<?php
/**
 * Database + site configuration for Ryder's Puppy Fort Factory.
 *
 * This is a deliberately vulnerable TEST application. Do not deploy it on a
 * public server. Adjust the credentials below for your local Apache/MySQL
 * (LAMP) setup, or override them with environment variables.
 *
 * The defaults use the dedicated lab application user `pff`, NOT the database
 * `root` account: modern MariaDB/MySQL authenticates `root` via the unix socket,
 * so a TCP login as `root` is refused regardless of password (and least
 * privilege is good practice even for a lab). The containerized lab provisions
 * this `pff` user automatically and passes the matching PFF_DB_* env vars, which
 * override the defaults below; for a manual LAMP setup create the user as shown
 * in puppy-fort-factory/README.md. These are lab-only throwaway credentials.
 */

define('DB_HOST', getenv('PFF_DB_HOST') ?: '127.0.0.1');
define('DB_USER', getenv('PFF_DB_USER') ?: 'pff');
define('DB_PASS', getenv('PFF_DB_PASS') !== false ? getenv('PFF_DB_PASS') : 'pff_lab_pw');
define('DB_NAME', getenv('PFF_DB_NAME') ?: 'puppy_fort');

define('SITE_NAME', "Ryder's Puppy Fort Factory");
