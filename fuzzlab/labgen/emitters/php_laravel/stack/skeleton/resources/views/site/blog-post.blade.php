{{-- Hand-authored (CC-LAB-0240, docs/LAB_PFF_JSON_TO_HTML_PLAN.md), not
     generated: rendered via the "html_list_view" tail
     (fuzzlab.labgen.emitters.php_laravel's single_statement.php.j2 complexity)
     for LABGEN-RPL-BLOGPOST (vulnerable) and LABGEN-RPL-BLOGPOST-BOUND
     (secure), which both `return view('site.blog-post', ['rows' => $rows])`
     with the same $rows shape (a LIST of `posts` rows). Byte-identical for
     both twins -- only the data differs (R5).

     Copy follows the real, pre-cutover page
     (`git show 876d2f9^:puppy-fort-factory/blog_post.php`), including its
     "Post not found." empty state. R6: the SQLite live-boot harness's
     `posts` table has only id/title/body, so `author`/`published_at` (real
     schema only) are rendered only when present. R1: the found state (the
     article plus its share/follow-up footer) is deliberately at least 300
     bytes longer than the not-found state -- guarded by a direct
     byte-length test. --}}
@extends('layouts.site')
@section('title', 'Blog')
@section('content')
    <p><a href="/blog_post.php">&larr; Back to the blog</a></p>
    @forelse ($rows as $row)
        <article class="blog-post" data-post-id="{{ $row->id }}">
            <h1>{{ $row->title }}</h1>
            @if (isset($row->author) && isset($row->published_at))
                <p class="muted">by {{ $row->author }} on {{ $row->published_at }}</p>
            @endif
            <div class="bio">{!! nl2br(e($row->body)) !!}</div>
            <footer class="post-footer">
                <p>Enjoyed this post? Share it with your pack using its
                    <a href="/blog_post.php?id={{ (int) $row->id }}">permanent link</a>.</p>
                <p>Questions about building or defending a fort?
                    <a href="/contact.php">Ask the Fort Factory team</a>, or
                    <a href="/newsletter.php">sign up for fort news</a> to hear about new posts first.</p>
            </footer>
        </article>
    @empty
        <p>Post not found.</p>
    @endforelse
@endsection
