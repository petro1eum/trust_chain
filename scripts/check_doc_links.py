#!/usr/bin/env python3
"""Fail if relative markdown links in docs/ point to missing files.

Shared across TrustChain repos: this file is the source-of-truth copy;
mirror it byte-identical into sibling repos (enforced via docs-links.yml).

Rules:
- http(s), mailto, #anchor — skipped.
- `file.md#anchor` — only the file part is checked (anchor is not validated).
- Paths escaping ROOT (e.g. `../../sibling_repo/...`) — treated as cross-repo
  references and **warned** (not failed). Prefer `https://github.com/...` URLs
  for cross-repo links in enterprise docs.
- Missing targets inside ROOT — hard failure.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def main() -> int:
    bad: list[str] = []
    warn: list[str] = []
    for md in sorted(ROOT.glob("docs/**/*.md")):
        if "/wiki/" in md.as_posix():
            continue
        text = md.read_text(encoding="utf-8", errors="replace")
        for m in LINK_RE.finditer(text):
            raw = m.group(1).strip().split()[0].strip('"').strip("'")
            if raw.startswith(("http://", "https://", "mailto:", "#")):
                continue
            if "://" in raw:
                continue
            # Strip anchor: `file.md#section` → `file.md`
            path_part = raw.split("#", 1)[0]
            if not path_part:
                continue  # pure anchor like "#top"
            target = (md.parent / path_part).resolve()
            try:
                target.relative_to(ROOT)
            except ValueError:
                warn.append(
                    f"{md.relative_to(ROOT)}: cross-repo ref {raw!r} (prefer https URL)"
                )
                continue
            if not target.exists():
                bad.append(
                    f"{md.relative_to(ROOT)}: missing {raw!r} -> {target.relative_to(ROOT)}"
                )
    if warn:
        print("Warnings (cross-repo links):\n" + "\n".join(warn))
    if bad:
        print("Broken relative links:\n" + "\n".join(bad))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
