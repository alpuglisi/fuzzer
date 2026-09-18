<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Blog';

/*
 * SECURE PAGE.
 * No user input reaches the query, and all output is escaped with e().
 */
$res = mysqli_query(
    $conn,
    "SELECT id, title, author, published_at, LEFT(body, 140) AS excerpt
     FROM posts ORDER BY published_at DESC, id DESC"
);

require __DIR__ . '/includes/header.php';
?>
<h1>The Fort Factory blog</h1>

<?php if (!$res || mysqli_num_rows($res) === 0): ?>
  <p>No posts yet. (Did you run <code>sql/002_blog.sql</code>?)</p>
<?php else: ?>
  <?php while ($p = mysqli_fetch_assoc($res)): ?>
    <article class="card" style="margin-bottom:14px">
      <h3><a href="blog_post.php?id=<?= (int)$p['id'] ?>"><?= e($p['title']) ?></a></h3>
      <p class="muted">by <?= e($p['author']) ?> on <?= e($p['published_at']) ?></p>
      <p><?= e($p['excerpt']) ?>…</p>
    </article>
  <?php endwhile; ?>
<?php endif; ?>
<?php require __DIR__ . '/includes/footer.php'; ?>
