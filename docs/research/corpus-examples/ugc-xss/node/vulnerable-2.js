/**
 * Source: gitalk/gitalk, src/component/comment.jsx (Comment render method).
 * License: MIT
 * Copyright (c) 2017 aotu.io
 *
 * Pattern: gitalk is gitment's actively-maintained successor (a widely used,
 * real GitHub-Issues-backed comment widget). It still renders each comment's
 * server-produced `body_html` via React's `dangerouslySetInnerHTML` with no
 * client-side sanitizer call in this render path — the same raw-HTML-sink
 * shape as gitment's (vulnerable-1.js), just via JSX's explicit escape hatch
 * instead of a template-literal `innerHTML` assignment. Recorded as a second,
 * independently-sourced instance of the same "trust the server-rendered
 * comment HTML" anti-pattern in a different, still-maintained real project.
 */

class Comment extends Component {
  // ... (surrounding like/edit/reply-button rendering omitted; see
  // repository for full file)

  render() {
    const { comment, replyCallback, likeCallback, enableEdit, reactions } = this.props

    return (
      <div className="gt-comment" id={`gt-comment-${comment.id}`}>
        {/* ... avatar/header markup omitted ... */}
        <div className="gt-comment-content">
          <div
            className="gt-comment-body markdown-body"
            dangerouslySetInnerHTML={{
              __html: comment.body_html
            }}
          />
        </div>
      </div>
    )
  }
}
