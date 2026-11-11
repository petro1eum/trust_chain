"""Execute notebooks in clean kernels; optional ephemeral Pro fixture is CI-only."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

import nbformat
from nbclient import NotebookClient
from jupyter_client import KernelManager


def run(path: Path, *, test_license: bool = False) -> dict:
    notebook = nbformat.read(path, as_version=4)
    nbformat.validate(notebook)
    notebook.cells = [c for c in notebook.cells if "install" not in c.metadata.get("tags", [])]
    if test_license:
        fixture = Path(__file__).resolve().parents[1] / "tests/testing_license.py"
        if not fixture.is_file():
            raise RuntimeError("Repository test fixture is unavailable")
        setup = (
            "import os, runpy\n"
            f"_fixture=runpy.run_path({str(fixture)!r})\n"
            "os.environ['TRUSTCHAIN_PRO_LICENSE']=_fixture['GOOD_V2_TOKEN']\n"
            "from trustchain_pro.licensing import invalidate_license_cache\n"
            "invalidate_license_cache()\n"
        )
        notebook.cells.insert(0, nbformat.v4.new_code_cell(setup))
    # No provider credentials, user .env, or inherited revocation endpoints.
    environment = {"PATH": str(Path(sys.executable).parent) + os.pathsep + os.defpath,
                   "LANG": "en_US.UTF-8", "PYTHONNOUSERSITE": "1"}
    with tempfile.TemporaryDirectory(prefix="trustchain-notebook-test-") as folder:
        environment["IPYTHONDIR"] = str(Path(folder) / "ipython")
        manager = KernelManager(kernel_name="python3")
        manager.kernel_spec.argv = [sys.executable, "-m", "ipykernel_launcher", "-f", "{connection_file}"]
        client = NotebookClient(notebook, km=manager, timeout=120,
                                resources={"metadata":{"path":folder}}, allow_errors=False)
        try:
            client.execute(env=environment)
        finally:
            # NotebookClient doesn't own an explicitly supplied kernel manager.
            if manager.has_kernel:
                manager.shutdown_kernel(now=True)
    return {"notebook":str(path), "code_cells":sum(c.cell_type=="code" for c in notebook.cells),
            "executed":True, "install_cells_skipped":True, "test_license":test_license,
            "live_model_called":False}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("notebooks", nargs="+")
    parser.add_argument("--test-license", action="store_true")
    args=parser.parse_args()
    failures=0
    for name in args.notebooks:
        try:
            print(json.dumps(run(Path(name).resolve(), test_license=args.test_license)), flush=True)
        except Exception as exc:
            failures+=1
            print(json.dumps({"notebook":name,"executed":False,"error":str(exc)}), flush=True)
    return 1 if failures else 0


if __name__=="__main__":
    raise SystemExit(main())
