// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics" (Phase 3, final batch, group 2 of 10). Closes this cell's
// remaining CWE-89 gap (distinct from vulnerable-2.js/idiomatic-2-altered.js,
// which cover this same cell's CWE-1336 SSTI-in-export group). Genuinely
// distinct third variant from vulnerable-1.js/idiomatic-1.js: a Sequelize
// ORM (not raw pg/knex) product-search endpoint, where the WHERE clause uses
// Sequelize's own parameterized operators correctly, but the ORDER BY column
// is built with sequelize.literal() from raw, unvalidated request input --
// the same "ORM query-builder misuse, not raw-concat" shape as vulnerable-1.js,
// in a different, independently common Node ORM.
const { Op } = require('sequelize');
const { sequelize, Product } = require('../models');

async function searchProducts(req, res, next) {
  try {
    const { q, category, sort_field, sort_dir } = req.query;

    const where = {};
    if (q) where.name = { [Op.like]: `%${q}%` };
    if (category) where.category = category;

    // VULNERABLE: sort_field/sort_dir come straight from the query string
    // and are interpolated into a raw SQL fragment via sequelize.literal(),
    // with no allowlist check against Product's real column names -- while
    // every other dynamic value in this same query (q, category) is bound
    // safely through Sequelize's own Op.like/equality operators.
    const products = await Product.findAll({
      where,
      order: [[sequelize.literal(`${sort_field || 'id'} ${sort_dir || 'ASC'}`)]],
    });

    res.json(products);
  } catch (err) {
    next(err);
  }
}

module.exports = { searchProducts };
