'use strict';

// Per-stack scaffold file (CR-LAB-0001 Addendum D: `scaffold_files`,
// rendered once per stack, never touched per generated cell). A single
// shared mysql2 connection pool every generated controller requires --
// mirrors php_current's shared $pdo handle, just via mysql2/promise's pool
// API instead of PDO.
//
// Configuration is read from the environment, never hard-coded, matching
// this project's D12 "credentials in the OS keyring / credential store,
// never committed" rule -- this file itself carries no secret.
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: process.env.LAB_DB_HOST || '127.0.0.1',
  port: Number(process.env.LAB_DB_PORT || 3306),
  user: process.env.LAB_DB_USER || 'lab',
  password: process.env.LAB_DB_PASSWORD || '',
  database: process.env.LAB_DB_NAME || 'fuzzlab_node_express',
  waitForConnections: true,
  connectionLimit: 10,
});

module.exports = pool;
