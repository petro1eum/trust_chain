# PostgreSQL log memory and byte compatibility

The PostgreSQL verifiable log keeps a Merkle frontier, one completed subtree
per occupied binary digit of the record count. It retains O(log N) digests,
not record bodies, all leaf hashes, or all tree levels. Startup reads the
history through a server-side cursor with a bounded prefetch of 64 records.
The memory bound includes the largest fetched records; it is not a bound on
the size of a single user record.

An unchanged committed HEAD avoids a history scan. A newer HEAD causes only
the additional rows to be streamed. Append catches up under the existing
database advisory lock and publishes its private candidate frontier only
after the record and HEAD commit together. No schema or signed-byte migration
is needed. Existing legacy and RFC 6962 hashing rules remain distinct.

Integrity verification always streams the entire history in one read-only,
repeatable-read snapshot. It does not trust the cached frontier as an
integrity oracle. Explicit rebuild also rereads all rows. Inclusion and
consistency proofs stream the necessary disjoint ranges of existing leaf
digests with bounded memory. Only the requested record body is read for an
inclusion proof, and the generated proof is checked against that body and the
computed HEAD before return. A corrupt digest index fails closed. These proofs
preserve the original format but cost O(N) digest reads in the worst case.
Persisted subtree indexes could reduce that cost in a future release.
The explicit `export_json()` API still materializes its requested output,
because its existing contract returns the complete JSON string.

## Reproducible verification

Use Python 3.12 and local Docker for the PostgreSQL 17 integration fixtures:

```sh
python -m pytest -o addopts= -q tests/test_pg_verifiable_log.py \
  tests/test_pg_merkle_adoption.py tests/test_pg_chaos.py \
  tests/test_rfc6962.py tests/test_merkle_incremental.py \
  tests/test_merkle_frontier.py tests/test_pg_streaming_log.py
```

The independent existing tree implementations are the root/proof oracles.
Additional tests cover every prefix, odd subtrees, restart, a bounded retained
heap, real Ed25519 signatures and wrong keys, failed HEAD writes, concurrent
writers, verification snapshots, tampered history behind an unchanged HEAD,
and a corrupted proof digest index.

A local macOS same-dataset experiment on 2026-10-29 used 100,000 synthetic
records (211,077,790 JSON bytes) in a temporary PostgreSQL container. Separate
processes loaded the old and new implementations against the same committed
HEAD; all roots and the sampled proofs matched.

| Scheme | Old loaded RSS | New loaded RSS | Old unchanged refresh | New unchanged refresh | Old/new proof time |
| --- | ---: | ---: | ---: | ---: | ---: |
| Legacy | 87.1 MiB | 61.6 MiB | 1.14 s | 0.003 s | 0.001 / 0.30 s |
| RFC 6962 | 307.5 MiB | 61.6 MiB | 1.29 s | 0.003 s | 0.25 / 0.25 s |

These are synthetic local measurements, not production RAM measurements or
capacity guarantees. Proof latency is the explicit memory/I/O tradeoff.

## Further disk compression research (not enabled by this release)

On 2026-10-29, a read-only production probe sampled 1,024 records each from
early, middle and recent positions in both chains: 6,144 held-out records.
Zstandard level 3, independently framed blocks of at most approximately 1 MiB,
reduced 16,266,597 raw JSON bytes to 2,600,108 bytes (6.26x). Every compressed
block was decompressed and compared byte-for-byte. PostgreSQL column storage
for these sampled values was already 12,729,512 bytes; the raw JSON ratio must
not be presented as a whole-database disk saving. Indexes, metadata, backups,
sample bias and block indexes also matter. A single 32 KiB dictionary trained
on early records compressed held-out individual records less than blocks did.

For a future storage layer, independently decodable Zstandard blocks plus a
sequence/operation index can preserve exact signed bytes. Record and block
size limits, codec versions, checksums, recovery, concurrent append and proof
lookup must be verified before migrating production. Never rewrite signed
history through a new JSON serializer merely to make it smaller.

Primary references:

- [Zstandard format, RFC 8878](https://www.rfc-editor.org/rfc/rfc8878.html): lossless frames and dictionaries.
- [PostgreSQL TOAST](https://www.postgresql.org/docs/16/storage-toast.html): existing per-value compression, not cross-row dictionaries.
- [Apache Parquet encodings](https://parquet.apache.org/docs/file-format/data-pages/encodings/): typed column dictionary/delta encodings, useful for an analytical projection.
- [Protocol Buffers serialization is not canonical](https://protobuf.dev/programming-guides/serialization-not-canonical/): a typed binary serializer alone is not a safe replacement for hashed historical bytes.
