// MANUFACTURED per docs/VULN_CORPUS_PAIR_MANUFACTURING_PLAN.md's "Per-pair
// mechanics" (Phase 3, final batch, group 2 of 10). Derived from
// vulnerable-3-altered.js's real Sequelize structure. Minimal-pair
// discipline: identical imports, identical WHERE-clause construction. The
// ONLY mechanism difference is the ORDER BY position: sort_field is checked
// against SORTABLE_COLUMNS (an explicit allowlist of Product's real column
// names) before being used at all, and Sequelize's own array-form `order`
// (rather than a raw sequelize.literal() string) is used once it's
// validated, letting Sequelize itself quote the identifier.
const { Op } = require('sequelize');
const { Product } = require('../models');

const SORTABLE_COLUMNS = new Set(['id', 'name', 'price', 'created_at']);

async function searchProducts(req, res, next) {
  try {
    const { q, category, sort_field, sort_dir } = req.query;

    const where = {};
    if (q) where.name = { [Op.like]: `%${q}%` };
    if (category) where.category = category;

    // IDIOMATIC: sort_field must be one of Product's real column names
    // before it's used in `order` at all; sort_dir is likewise restricted
    // to the only two valid SQL directions. Sequelize's array-form `order`
    // (not a raw literal string) quotes the identifier itself once it's
    // been validated.
    const column = SORTABLE_COLUMNS.has(sort_field) ? sort_field : 'id';
    const direction = sort_dir === 'DESC' ? 'DESC' : 'ASC';

    const products = await Product.findAll({
      where,
      order: [[column, direction]],
    });

    res.json(products);
  } catch (err) {
    next(err);
  }
}

module.exports = { searchProducts };
