# TrustChain Notice

## Open Source License

TrustChain is released under the MIT License. See [LICENSE](LICENSE) for details.

## Contributing

We welcome contributions! By submitting a pull request, you agree to license your 
contribution under the MIT License and certify that you have the right to do so
([Developer Certificate of Origin](https://developercertificate.org/)).

### Contributors

- **Ed Cherednik** — Creator and maintainer

## Third-Party Licenses

TrustChain depends on the following open source packages:

| Package | License | Use |
|---------|---------|-----|
| [PyNaCl](https://github.com/pyca/pynacl) | Apache 2.0 | Ed25519 cryptography |
| [cryptography](https://github.com/pyca/cryptography) | Apache 2.0 / BSD | Cryptographic primitives |
| [Pydantic](https://github.com/pydantic/pydantic) | MIT | Data validation |
| [msgpack](https://github.com/msgpack/msgpack-python) | Apache 2.0 | Binary serialization |
| [Click](https://github.com/pallets/click) | BSD-3-Clause | CLI framework |
| [Rich](https://github.com/Textualize/rich) | MIT | Terminal formatting |
| [Typer](https://github.com/tiangolo/typer) | MIT | CLI builder |
| [PyYAML](https://github.com/yaml/pyyaml) | MIT | YAML parsing |
| [python-dotenv](https://github.com/theskumar/python-dotenv) | BSD-3-Clause | Environment variables |

Optional dependencies (when installed):
- **Redis** (BSD-3-Clause) — Distributed nonce storage
- **LangChain** (MIT) — Agent framework integration
- **MCP SDK** (MIT) — Claude Desktop integration
- **OpenAI/Anthropic SDKs** (MIT) — LLM integrations

## Commercial & Enterprise

**TrustChain Core** (this repository) is and will remain **free and open source**.

For organizations requiring:
- Enterprise support & SLAs
- C++ Verifier Core (high-throughput verification)
- Regulated environment deployment (banking, defence, gov)
- Custom integrations & consulting
- Audit-ready documentation and compliance packages

Contact: **edcherednik@gmail.com**

## Roadmap Note

Future enterprise features (C++ verifier, HSM integration, FIPS compliance) 
may be offered under a commercial license. The Python SDK and core protocol 
implementation will remain MIT licensed.

## Trademark

"TrustChain" is a trademark of Ed Cherednik. Use of the name for commercial
products requires explicit permission.
