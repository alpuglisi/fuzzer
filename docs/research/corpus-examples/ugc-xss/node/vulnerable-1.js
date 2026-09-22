/**
 * Source: imsun/gitment, src/theme/default.js, renderComments().
 * License: MIT
 * Copyright (c) 2016 imsun
 *
 * Pattern: gitment is a real, published GitHub-Issues-backed comment widget
 * (client-side JS, embedded in static sites/blogs). Each comment's
 * `body_html` (server-rendered Markdown of the raw comment body) is
 * interpolated directly into a template-literal string that is then assigned
 * to `commentItem.innerHTML` — a stored-XSS shape distinct from fuzzlab's
 * existing basic reflected html_body case: the payload is a *comment* that
 * every later visitor's browser re-renders as live HTML, with zero
 * client-side sanitization (no DOMPurify/escaping call anywhere in this
 * render path). gitment was later succeeded by gitalk (see vulnerable-2.js)
 * specifically because of long-unaddressed issues like this one.
 */

function renderComments({ meta, comments, commentReactions, currentPage, user, error }, instance) {
  // ... (surrounding pagination/header rendering omitted; see repository
  // for full file)

  comments.forEach(comment => {
    const createDate = new Date(comment.created_at)
    const updateDate = new Date(comment.updated_at)
    const commentItem = document.createElement('li')
    commentItem.className = 'gitment-comment'
    commentItem.innerHTML = `
      <a class="gitment-comment-avatar" href="${comment.user.html_url}" target="_blank">
        <img class="gitment-comment-avatar-img" src="${comment.user.avatar_url}"/>
      </a>
      <div class="gitment-comment-main">
        <div class="gitment-comment-header">
          <a class="gitment-comment-name" href="${comment.user.html_url}" target="_blank">
            ${comment.user.login}
          </a>
          commented on
          <span title="${createDate}">${createDate.toDateString()}</span>
          ${ createDate.toString() !== updateDate.toString()
            ? ` • <span title="comment was edited at ${updateDate}">edited</span>`
            : ''
          }
          <div class="gitment-comment-like-btn">${'<icon>'} ${comment.reactions.heart || ''}</div>
        </div>
        <div class="gitment-comment-body gitment-markdown">${comment.body_html}</div>
      </div>
    `
    // ... (like-button wiring omitted; see repository for full file)
  })
}
