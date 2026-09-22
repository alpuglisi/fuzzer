'use strict';

const { getDb } = require('../database');
const { rows, row } = require('../database/helpers');

const livrosController = {
  async listar(req, res) {
    const knex = getDb();
    const { busca, autor, categoria, editora, idioma, ano, disponivel, page = 1, limit = 20 } = req.query;
    const offset = (Number(page) - 1) * Number(limit);

    let where = [];
    let params = [];

    if (busca) {
      where.push('(l.titulo LIKE ? OR l.isbn LIKE ? OR l.subtitulo LIKE ?)');
      params.push(`%${busca}%`, `%${busca}%`, `%${busca}%`);
    }
    if (autor)     { where.push('a.nome LIKE ?');    params.push(`%${autor}%`); }
    if (categoria) { where.push('c.nome LIKE ?');    params.push(`%${categoria}%`); }
    if (editora)   { where.push('ed.nome LIKE ?');   params.push(`%${editora}%`); }
    if (idioma)    { where.push('l.idioma LIKE ?');  params.push(`%${idioma}%`); }
    if (ano)       { where.push('l.ano_publicacao = ?'); params.push(Number(ano)); }

    let havingDisp = '';
    if (disponivel === '1' || disponivel === 'true') havingDisp = 'HAVING exemplares_disponiveis > 0';
    if (disponivel === '0' || disponivel === 'false') havingDisp = 'HAVING exemplares_disponiveis = 0';

    const whereClause = where.length ? 'WHERE ' + where.join(' AND ') : '';

    const totalRow = row(await knex.raw(`
      SELECT COUNT(DISTINCT l.id) as total
      FROM livros l
      LEFT JOIN autores a  ON a.id  = l.id_autor
      LEFT JOIN categorias c ON c.id = l.id_categoria
      LEFT JOIN editoras ed  ON ed.id = l.id_editora
      ${whereClause}
    `, params));

    const livros = rows(await knex.raw(`
      SELECT l.id, l.isbn, l.titulo, l.subtitulo, l.ano_publicacao, l.edicao,
             l.num_paginas, l.idioma, l.localizacao, l.descricao, l.capa_url,
             (CASE WHEN l.capa_base64 IS NOT NULL OR l.capa_url IS NOT NULL THEN 1 ELSE 0 END) AS tem_capa,
             a.id as autor_id, a.nome as autor_nome,
             ed.id as editora_id, ed.nome as editora_nome,
             c.id as categoria_id, c.nome as categoria_nome,
             COUNT(e.id) as total_exemplares,
             SUM(CASE WHEN e.disponivel = 1 THEN 1 ELSE 0 END) as exemplares_disponiveis
      FROM livros l
      LEFT JOIN autores a   ON a.id  = l.id_autor
      LEFT JOIN editoras ed ON ed.id = l.id_editora
      LEFT JOIN categorias c ON c.id = l.id_categoria
      LEFT JOIN exemplares e ON e.id_livro = l.id
      ${whereClause}
      GROUP BY l.id, a.id, a.nome, ed.id, ed.nome, c.id, c.nome
      ${havingDisp}
      ORDER BY l.titulo
      LIMIT ? OFFSET ?
    `, [...params, Number(limit), offset]));

    res.json({
      total: totalRow.total,
      pagina: Number(page),
      limite: Number(limit),
      livros,
    });
  },

  async buscarPorId(req, res) {
    const knex = getDb();
    const livro = row(await knex.raw(`
      SELECT l.*,
             a.id as autor_id, a.nome as autor_nome, a.nacionalidade as autor_nacionalidade,
             ed.id as editora_id, ed.nome as editora_nome,
             c.id as categoria_id, c.nome as categoria_nome
      FROM livros l
      LEFT JOIN autores a   ON a.id  = l.id_autor
      LEFT JOIN editoras ed ON ed.id = l.id_editora
      LEFT JOIN categorias c ON c.id = l.id_categoria
      WHERE l.id = ?
    `, [req.params.id]));
    if (!livro) return res.status(404).json({ erro: 'Livro não encontrado.' });

    const exemplares = rows(await knex.raw(`
      SELECT e.id, e.num_tombo, e.condicao, e.disponivel, e.data_aquisicao
      FROM exemplares e
      WHERE e.id_livro = ?
      ORDER BY e.num_tombo
    `, [livro.id]));

    res.json({ ...livro, exemplares });
  },

  async criar(req, res) {
    const knex = getDb();
    const { isbn, titulo, subtitulo, id_autor, id_editora, id_categoria,
            ano_publicacao, edicao, num_paginas, idioma, localizacao, descricao,
            capa_url, capa_base64, capa_mime } = req.body;

    try {
      const result = await knex('livros').insert({
        isbn:           isbn           || null,
        titulo,
        subtitulo:      subtitulo      || null,
        id_autor:       id_autor       || null,
        id_editora:     id_editora     || null,
        id_categoria:   id_categoria   || null,
        ano_publicacao: ano_publicacao || null,
        edicao:         edicao         || null,
        num_paginas:    num_paginas    || null,
        idioma:         idioma         || 'Português',
        localizacao:    localizacao    || null,
        descricao:      descricao      || null,
        capa_url:       capa_url       || null,
        capa_mime:      capa_mime      || 'image/jpeg',
        capa_base64:    capa_base64    || null,
      }).returning('id');
      const id = typeof result[0] === 'object' ? result[0].id : result[0];
      res.status(201).json({ id, titulo });
    } catch (e) {
      if (e.message.includes('UNIQUE') || e.message.includes('unique')) return res.status(409).json({ erro: 'ISBN já cadastrado.' });
      throw e;
    }
  },

  async atualizar(req, res) {
    const knex = getDb();
    const atual = row(await knex.raw('SELECT * FROM livros WHERE id = ?', [req.params.id]));
    if (!atual) return res.status(404).json({ erro: 'Livro não encontrado.' });

    const campos = ['isbn', 'titulo', 'subtitulo', 'id_autor', 'id_editora', 'id_categoria',
                    'ano_publicacao', 'edicao', 'num_paginas', 'idioma', 'localizacao', 'descricao',
                    'capa_url', 'capa_mime', 'capa_base64'];
    const updates = {};
    for (const c of campos) {
      updates[c] = req.body[c] !== undefined ? req.body[c] : atual[c];
    }

    try {
      await knex('livros').where({ id: req.params.id }).update(updates);
      res.json({ mensagem: 'Livro atualizado com sucesso.' });
    } catch (e) {
      if (e.message.includes('UNIQUE') || e.message.includes('unique')) return res.status(409).json({ erro: 'ISBN já cadastrado em outro livro.' });
      throw e;
    }
  },

  /* GET /api/livros/:id/capa — serve cover image from DB */
  async servirCapa(req, res) {
    const knex = getDb();
    const livro = row(await knex.raw('SELECT capa_base64, capa_mime, capa_url FROM livros WHERE id = ?', [req.params.id]));
    if (!livro) return res.status(404).json({ erro: 'Livro não encontrado.' });

    if (livro.capa_base64) {
      const buf = Buffer.from(livro.capa_base64, 'base64');
      res.set('Content-Type', livro.capa_mime || 'image/jpeg');
      res.set('Cache-Control', 'public, max-age=86400');
      return res.send(buf);
    }

    if (livro.capa_url) {
      return res.redirect(livro.capa_url);
    }

    res.status(404).json({ erro: 'Capa não disponível.' });
  },

  async remover(req, res) {
    const knex = getDb();
    const livro = row(await knex.raw('SELECT * FROM livros WHERE id = ?', [req.params.id]));
    if (!livro) return res.status(404).json({ erro: 'Livro não encontrado.' });
    const empAtivos = row(await knex.raw(`
      SELECT COUNT(*) as c FROM emprestimos em
      JOIN exemplares ex ON ex.id = em.id_exemplar
      WHERE ex.id_livro = ? AND em.status IN ('Ativo', 'Atrasado')
    `, [req.params.id]));
    if (Number(empAtivos.c) > 0) return res.status(409).json({ erro: 'Livro possui empréstimos ativos. Não pode ser removido.' });
    await knex('livros').where({ id: req.params.id }).delete();
    res.json({ mensagem: 'Livro removido com sucesso.' });
  },

  // --- Exemplares ---
  async listarExemplares(req, res) {
    const knex = getDb();
    const livro = row(await knex.raw('SELECT id, titulo FROM livros WHERE id = ?', [req.params.id]));
    if (!livro) return res.status(404).json({ erro: 'Livro não encontrado.' });
    const exemplares = rows(await knex.raw('SELECT * FROM exemplares WHERE id_livro = ? ORDER BY num_tombo', [req.params.id]));
    res.json({ livro, exemplares });
  },

  async adicionarExemplar(req, res) {
    const knex = getDb();
    const livro = row(await knex.raw('SELECT id FROM livros WHERE id = ?', [req.params.id]));
    if (!livro) return res.status(404).json({ erro: 'Livro não encontrado.' });
    const { num_tombo, condicao, data_aquisicao } = req.body;
    try {
      const result = await knex('exemplares').insert({
        id_livro:       Number(req.params.id),
        num_tombo,
        condicao:       condicao       || 'Bom',
        data_aquisicao: data_aquisicao || null,
      }).returning('id');
      const id = typeof result[0] === 'object' ? result[0].id : result[0];
      res.status(201).json({ id, id_livro: Number(req.params.id), num_tombo, condicao });
    } catch (e) {
      if (e.message.includes('UNIQUE') || e.message.includes('unique')) return res.status(409).json({ erro: 'Número de tombo já cadastrado.' });
      throw e;
    }
  },

  async atualizarExemplar(req, res) {
    const knex = getDb();
    const exemplar = row(await knex.raw('SELECT * FROM exemplares WHERE id = ? AND id_livro = ?', [req.params.exemplarId, req.params.id]));
    if (!exemplar) return res.status(404).json({ erro: 'Exemplar não encontrado.' });
    const { condicao, data_aquisicao } = req.body;
    await knex('exemplares').where({ id: exemplar.id }).update({
      condicao:       condicao       ?? exemplar.condicao,
      data_aquisicao: data_aquisicao ?? exemplar.data_aquisicao,
    });
    res.json({ mensagem: 'Exemplar atualizado com sucesso.' });
  },

  async removerExemplar(req, res) {
    const knex = getDb();
    const exemplar = row(await knex.raw('SELECT * FROM exemplares WHERE id = ? AND id_livro = ?', [req.params.exemplarId, req.params.id]));
    if (!exemplar) return res.status(404).json({ erro: 'Exemplar não encontrado.' });
    if (!exemplar.disponivel) return res.status(409).json({ erro: 'Exemplar está emprestado. Não pode ser removido.' });
    await knex('exemplares').where({ id: exemplar.id }).delete();
    res.json({ mensagem: 'Exemplar removido com sucesso.' });
  },
};

module.exports = livrosController;
