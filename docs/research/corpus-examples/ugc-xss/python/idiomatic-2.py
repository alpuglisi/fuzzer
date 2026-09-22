"""
Source: hotosm/tasking-manager, backend/models/postgis/task.py,
TaskHistory.set_comment_action().
License: BSD 2-Clause
Copyright (c) 2017, Humanitarian OpenStreetMap Team

Pattern: HOT Tasking Manager is a real, actively used production application
(OpenStreetMap task-mapping coordination). Its task-comment feature (users
leave free-text comments on mapping tasks) runs every comment through
`bleach.clean()` with its default allowlist before persisting it as task
history -- a second, independently-sourced real-world instance of the same
"sanitize the stored comment text with an allowlist HTML sanitizer" idiom as
python/idiomatic-1.py, from a different, much larger production codebase.
"""

import bleach


class TaskHistory:
    # ... (surrounding TaskHistory action-encoding methods omitted; see
    # repository for full file)

    def set_comment_action(comment: str) -> str:
        clean_comment = bleach.clean(comment)  # Ensure no harmful scripts or tags
        return TaskAction.COMMENT.name, clean_comment
