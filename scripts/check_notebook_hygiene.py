"""Saved notebooks must contain no execution output or implicit model opt-in."""
from pathlib import Path
import json
import re
root = Path(__file__).resolve().parents[1]
errors = []
for path in sorted((root / "examples").glob("*.ipynb")):
    book = json.loads(path.read_text())
    for index, cell in enumerate(book["cells"]):
        if cell["cell_type"] != "code": continue
        source = "".join(cell["source"])
        if cell.get("outputs") or cell.get("execution_count") is not None:
            errors.append(f"{path.name}:{index}: saved execution output")
        if re.search(r"(?<![\w.])eval\s*\(", source):
            errors.append(f"{path.name}:{index}: unbounded eval")
        if re.search(r"(?:api_key|API_KEY|OPENROUTER_API_KEY)\s*\[", source):
            errors.append(f"{path.name}:{index}: credential fragment")
if errors: raise SystemExit("\n".join(errors))
print("Notebook output, evaluation and credential checks passed")
