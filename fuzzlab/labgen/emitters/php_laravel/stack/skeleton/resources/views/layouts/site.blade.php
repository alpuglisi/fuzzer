<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>@yield('title', 'Puppy Fort Factory')</title>
    <style>
        body { font-family: Arial, Helvetica, sans-serif; margin: 0; background: #f5f5f0; color: #222; }
        header { background: #6b4423; color: #fff; padding: 16px 24px; }
        header h1 { margin: 0 0 8px 0; font-size: 20px; }
        header nav a { color: #fff; margin-right: 14px; text-decoration: none; font-size: 13px; }
        header nav a:hover { text-decoration: underline; }
        main { max-width: 860px; margin: 24px auto; background: #fff; padding: 24px; border: 1px solid #ddd; }
        footer { text-align: center; color: #888; font-size: 12px; padding: 16px; }
        table { border-collapse: collapse; width: 100%; }
        table th, table td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; }
        form label { display: block; margin-top: 10px; font-size: 13px; }
        form input, form textarea { width: 100%; box-sizing: border-box; padding: 6px; margin-top: 2px; }
        form button { margin-top: 14px; padding: 8px 16px; }
        .site-list a { display: block; margin: 4px 0; }
    </style>
</head>
<body>
<header>
    <h1>Puppy Fort Factory</h1>
    <nav>
        <a href="/">Home</a>
        <a href="/search.php">Search</a>
        <a href="/products.php">Products</a>
        <a href="/product.php">Product</a>
        <a href="/blog_post.php">Blog</a>
        <a href="/reviews.php">Reviews</a>
        <a href="/feedback.php">Feedback</a>
        <a href="/profile.php">Profile</a>
        <a href="/login.php">Log in</a>
        <a href="/register.php">Register</a>
        <a href="/contact.php">Contact</a>
        <a href="/newsletter.php">Newsletter</a>
        <a href="/catalog">Catalog</a>
    </nav>
</header>
<main>
@yield('content')
</main>
<footer>Puppy Fort Factory &mdash; lab-only, authorized-testing target.</footer>
</body>
</html>
