<?php
/**
 * Database + site configuration for Ryder's Puppy Fort Factory.
 *
 * This is a deliberately vulnerable TEST application. Do not deploy it on a
 * public server. Adjust the credentials below for your local Apache/MySQL
 * (LAMP) setup, or override them with environment variables.
 */

define('DB_HOST', getenv('PFF_DB_HOST') ?: '127.0.0.1');
define('DB_USER', getenv('PFF_DB_USER') ?: 'root');
define('DB_PASS', getenv('PFF_DB_PASS') !== false ? getenv('PFF_DB_PASS') : '');
define('DB_NAME', getenv('PFF_DB_NAME') ?: 'puppy_fort');

define('SITE_NAME', "Ryder's Puppy Fort Factory");
