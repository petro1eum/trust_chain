# TrustChain notebooks and examples

All five notebooks were executed in **Google Colab Python 3.13.18 with TrustChain
3.3.0 on 13 November 2026**, each in a fresh hosted CPU runtime. They use synthetic
data and work without TrustChain Pro, a Pro license or a model API key. Installation cells use the current
kernel's `%pip`; saved execution outputs in the source `.ipynb` files are cleared before publication.
[Read the public catalog with executed HTML previews](https://petro1eum.github.io/trust_chain/notebooks.html).

| Notebook | Learn | External services |
|---|---|---|
| [Tutorial](trustchain_tutorial.ipynb) | Signed tool calls, chaining, tenants and tamper rejection | None |
| [Receipts](trustchain_receipts.ipynb) | Portable `.tcreceipt` files and pinned-key verification | None |
| [Advanced](trustchain_advanced.ipynb) | Key persistence, batch operations, tenant separation and optional integrations | Optional Redis/framework examples |
| [LLM tool boundary](trustchain_llm.ipynb) | Validate proposals, execute bounded arithmetic and verify receipts | OpenRouter only after explicit opt-in |
| [Full demo](trustchain_full_demo.ipynb) | Complete synthetic agent workflow and audit export | OpenRouter only after explicit opt-in |

The offline worker is a fixture, not a real model call. Live provider sections
require credentials and a model configured outside the notebook; no key fragments
are printed. Signatures prove attribution and byte integrity, not factual truth,
business acceptance or authorization for another action.

## Confidential data — Pro

[FactCrypt overview](https://petro1eum.github.io/trust_chain/factcrypt.html) explains
source encryption, typed references, agent permissions and local calculation.
The [public walkthrough](https://petro1eum.github.io/trust_chain/factcrypt-demo.html)
shows a recorded synthetic cycle. The full FactCrypt notebook and runtime are
supplied through [licensed private Pro access](https://petro1eum.github.io/trust_chain/pro.html),
not public PyPI. Public examples do not make the Pro implementation part of OSS.

[Documentation index](https://petro1eum.github.io/trust_chain/documentation.html) ·
[Security model](../docs/ATTRIBUTION_AND_VALIDITY.md) · [Receipts reference](../docs/RECEIPTS.md).

## Verified in Colab

| Notebook | Original code cells completed, including installation | Result |
|---|---:|---|
| Tutorial | 15 / 15 | PASS |
| Advanced | 8 / 8 | PASS |
| LLM tool boundary | 5 / 5 | PASS |
| Full demo | 11 / 11 | PASS |
| Receipts | 5 / 5 | PASS |

The browser runs included two additional diagnostic cells per notebook: before
installation (Core, Pro and its license absent) and after execution (Pro and its
license still absent, no new `pip check` conflicts). All 44 original code cells
ran, with zero execution errors. Saved `.ipynb` execution counts, Colab success
metadata and code were checked against the canonical sources. These are observed
runs with consistency checks, not a cryptographic cloud-execution attestation.
[Published run metadata and source hashes](../docs/notebooks/manifest.json).

Tutorial and Advanced now install only the dependencies their cells use. The
previous broad extras/upgrades pulled a newer OpenTelemetry SDK that conflicted
with Colab's preinstalled Google ADK. No conflict was added by the corrected
installations. The Colab base image itself reported `ipython 7.34.0 requires jedi,
which is not installed` before and after all five runs.

The live model branches stayed off. Redis was unavailable and its documented
fallback executed; PostgreSQL also used the in-memory fallback without a DSN.
This run proves the default OSS notebook workflow, not external-service setup.
To reproduce it, open a notebook in Colab, connect a new CPU runtime, and use
**Run all**, including its `%pip` cell. No private wheel or Pro license is needed.

## Refresh the public HTML previews

To import saved, browser-observed Colab runs with the preflight/postflight records
described above, use `scripts/import_colab_runs.py --run tutorial=/path/to/tutorial.executed.ipynb`
and supply another `--run NAME=PATH` for each of `advanced`, `llm`, `full_demo`, and
`receipts`. It checks all five runs before writing: exact original code, sequential
execution counts, successful cells, distinct runtimes and no new dependency
conflicts. It publishes original code and outputs only; Drive identity metadata
and diagnostic cells are excluded. The resulting previews include installation.

For a separate **local** check (which does not prove Colab installation):

From an environment with the notebook dependencies and `nbconvert` installed:

```sh
python scripts/check_notebooks.py --preview-dir docs/notebooks examples/*.ipynb
```

This runs the five canonical OSS notebooks in fresh local kernels, without
provider credentials, and saves the actual outputs plus source hashes in
`docs/notebooks/manifest.json`. Installation cells are omitted because dependencies
are installed first. It rejects Pro test-license mode and noncanonical notebooks.
Review the generated outputs before publication. The source notebooks stay clean.
