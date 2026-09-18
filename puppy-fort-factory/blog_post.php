<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/functions.php';
$page_title = 'Blog';

/*
 * !!! VULNERABLE PAGE - SQL INJECTION (blind-friendly) !!!
 *
 * The `id` GET parameter is concatenated straight into the query. Unlike
 * product.php, this page prints NO database errors and shows the same "post not
 * found" for any empty result, so it is a good boolean/time-based BLIND target.
 *
 *   blog_post.php?id=1 AND 1=1        -> post renders (true)
 *   blog_post.php?id=1 AND 1=2        -> "not found" (false)
 *   blog_post.php?id=1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)   -> delay (time-based)
 */
$id = $_GET['id'] ?? '1';
$sql = "SELECT id, title, author, body, published_at FROM posts WHERE id = $id";
$res = @mysqli_query($conn, $sql);   // errors intentionally not surfaced
$post = $res ? mysqli_fetch_assoc($res) : null;

require __DIR__ . '/includes/header.php';
?>
<p><a href="blog.php">&larr; Back to the blog</a></p>

<?php if (!$post): ?>
  <p>Post not found.</p>
<?php else: ?>
  <article>
    <h1><?= e($post['title']) ?></h1>
    <p class="muted">by <?= e($post['author']) ?> on <?= e($post['published_at']) ?></p>
    <div class="bio"><?= nl2br(e($post['body'])) ?></div>
  </article>
<?php endif; ?>
<?php require __DIR__ . '/includes/footer.php'; ?>
