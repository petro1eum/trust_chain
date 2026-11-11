"""Check the static documentation site, including HTML paths and fragment targets."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit
import sys

ROOT = Path(__file__).resolve().parents[1] / "docs"


class Page(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.links, self.ids = [], set()
        self.feed(text)
    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if attrs.get("id"):
            self.ids.add(attrs["id"])
        for attr in ("href", "src"):
            if attr in attrs and not attrs[attr].startswith(("data:", "javascript:")):
                self.links.append(attrs[attr])


def main():
    pages = {p.resolve(): Page(p.read_text()) for p in ROOT.rglob("*.html")}
    errors = []
    for path, page in pages.items():
        for link in page.links:
            parsed = urlsplit(link)
            if parsed.scheme or parsed.netloc or parsed.path.startswith("/"):
                continue
            target = (path.parent / unquote(parsed.path)).resolve() if parsed.path else path
            if not target.is_relative_to(ROOT):
                errors.append(f"{path.name}: target outside published docs: {link}")
            elif not target.exists():
                errors.append(f"{path.name}: missing {link}")
            elif parsed.fragment and target in pages and unquote(parsed.fragment) not in pages[target].ids:
                errors.append(f"{path.name}: missing fragment {link}")
    for error in errors:
        print(error)
    if not errors:
        print(f"{len(pages)} documentation pages: local paths and anchors verified")
    return bool(errors)


if __name__ == "__main__":
    sys.exit(main())
