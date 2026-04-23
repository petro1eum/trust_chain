"""Default reversible pairs for common categories (extend in your agent)."""

from __future__ import annotations

# Keys = forward tool ids often seen in demos; values = suggested reverse id.
BUILTIN_REVERSIBLE_MAP: dict[str, str] = {
    "file_write": "file_restore_from_snapshot",
    "http_post": "http_delete_or_noop",
    "db_insert": "db_delete_row",
    "email_send": "email_send_correction",
    "demo_tool": "demo_undo",
}
