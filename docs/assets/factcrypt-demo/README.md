# FactCrypt public example evidence

Recorded on 11 November 2026 with synthetic data and a test Platform agent.
The worker was deterministic, network-isolated and had no decryption key.
The owner replay produced 10002.00 + 2399.70 = 12401.70 RUB.

The test permission was revoked after acceptance and is now expired. The receipt
is historical evidence, not a currently usable source-access grant.

Pinned **public** Ed25519 keys for this example:

- Platform authority: `xM9W7VFCC7BeRjvbr1L3aDQYNOKJsAbwLbX5RJ01oHs=`
- Source: `UOeCdkJhrJLrB3zdDiS/FxPqY4BfgIo87+NCI4nfx+g=`
- Owner result signer: `xNw/E2YLP/Om1QMwHoaGHaFdmeXNWHRKA/nVX2qSKYo=`

The browser verifies signatures and links the canonical JSON export, plan and
encrypted-result digests. It does not decrypt, validate the full FactCrypt
protocol, establish CA identity/current authorization, or prove business logic.
The plaintext `result.md` is a separately disclosed synthetic owner output;
the public browser checks do not authenticate that plaintext against ciphertext.
The fixture pins are delivered by this site, not an independent trust anchor.

No vault, private key, license token, Pro wheel or Pro implementation is included.
TrustChain Pro is a paid library supplied through authorized private distribution.
