# TrustChain notebooks and examples

The notebooks below run with Python 3.12 and TrustChain 3.3. They use synthetic
data and work without a model API key. Installation cells use the current
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

## Refresh the public HTML previews

From an environment with the notebook dependencies and `nbconvert` installed:

```sh
python scripts/check_notebooks.py --preview-dir docs/notebooks examples/*.ipynb
```

This runs the five canonical OSS notebooks in fresh local kernels, without
provider credentials, and saves the actual outputs plus source hashes in
`docs/notebooks/manifest.json`. Installation cells are omitted because dependencies
are installed first. It rejects Pro test-license mode and noncanonical notebooks.
Review the generated outputs before publication. The source notebooks stay clean.
