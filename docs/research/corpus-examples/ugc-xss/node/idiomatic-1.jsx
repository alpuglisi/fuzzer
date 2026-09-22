/**
 * Source: MeetDOD/CareerInsight, frontend/src/Riverflow/AnswerList.jsx.
 * License: MIT
 * Copyright (c) 2025 Meet Ashok Dodiya
 *
 * Pattern: a real Q&A-style app (answers + threaded comments) also uses
 * `dangerouslySetInnerHTML` to render a stored comment body as rich HTML,
 * but first pipes it through `DOMPurify.sanitize()` — a real, actively
 * maintained allowlist-based HTML sanitizer — before handing the result to
 * React. This is the idiomatic/safe counterpart to vulnerable-1.js and
 * vulnerable-2.js's un-sanitized `dangerouslySetInnerHTML`/`innerHTML` of a
 * comment body: same sink shape, sanitizer interposed.
 */

import DOMPurify from "dompurify";

function AnswerList({ answers, comments /* , ...otherProps */ }) {
  // ... (surrounding answer-list/reply-form rendering omitted; see
  // repository for full file)

  return (
    <div>
      {comments[/* answer._id */]?.map((comment) => (
        <div key={comment._id} className="relative flex items-start gap-3">
          <img
            src={comment.author?.photo || "/default-avatar.png"}
            alt="User Avatar"
            className="w-8 h-8 rounded-full border border-primary"
          />
          <div className="p-3 rounded-lg w-full">
            <span className="font-medium text-sm">{comment.author?.fullName || "Anonymous"}</span>
            <p className="text-xs text-gray-400">{new Date(comment.createdAt).toLocaleString()}</p>
            <p className="text-sm mt-1" dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.body) }}></p>
          </div>
        </div>
      ))}
    </div>
  );
}
