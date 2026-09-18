<?php
require_once __DIR__ . '/functions.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= isset($page_title) ? e($page_title) . ' · ' : '' ?><?= e(SITE_NAME) ?></title>
  <link rel="stylesheet" href="assets/css/style.css">
  <script src="assets/js/site.js" defer></script>
</head>
<body>
  <header class="site-header">
    <div class="wrap header-inner">
      <a class="brand" href="index.php">🐾 Puppy Fort Factory</a>
      <form class="search-mini" action="search.php" method="get" role="search">
        <input type="text" name="q" placeholder="Search forts, chews, treats...">
      </form>
      <nav class="main-nav">
        <a href="products.php">Shop</a>
        <a href="blog.php">Blog</a>
        <a href="about.php">About</a>
        <a href="contact.php">Contact</a>
        <a href="cart.php">Cart</a>
        <?php if (is_logged_in()): ?>
          <a href="profile.php">Profile</a>
          <a href="logout.php">Logout</a>
        <?php else: ?>
          <a href="login.php">Login</a>
          <a href="register.php">Register</a>
        <?php endif; ?>
      </nav>
    </div>
  </header>
  <!-- JS injects the "Discover" links here (empty for a basic spider). -->
  <div id="js-discover" class="subnav"></div>
  <main class="wrap page">
