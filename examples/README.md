# TrustChain notebooks and examples

The notebooks below run with Python 3.12 and TrustChain 3.3. They use synthetic
data and work without a model API key. Installation cells use the current
kernel's `%pip`; saved execution outputs are cleared before publication.

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
The [full FactCrypt notebook](https://github.com/petro1eum/trust_chain_pro/blob/main/examples/trustchain_factcrypt.ipynb)
requires access to the private Pro package and a valid Pro license. Its use of
public APIs does not make the Pro implementation part of the OSS package.

[Documentation index](https://petro1eum.github.io/trust_chain/documentation.html) ·
[Security model](../docs/ATTRIBUTION_AND_VALIDITY.md) · [Receipts reference](../docs/RECEIPTS.md).
