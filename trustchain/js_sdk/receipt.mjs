/**
 * TrustChain Receipt — портативный объект «доказательство подписи».
 *
 * Файл даёт минимальный, zero-dependency API, совместимый и с Node (≥18,
 * webcrypto), и с современными браузерами.  Криптография — исключительно
 * `crypto.subtle` (Ed25519).  Канонизация JSON — побайтовая копия Python
 * ``trustchain.v2.signer._build_canonical_data`` + ``json.dumps(sort_keys=True,
 * separators=(",", ":"))``.  Любое расхождение = ломаные квитанции.
 *
 * Публичный контракт:
 *
 *   canonicalize(value)                         → string
 *   buildCanonicalEnvelope(envelope)            → Uint8Array
 *   verifyReceipt(receipt[, options])           → Promise<ReceiptVerification>
 *   loadReceipt(input)                          → Promise<Receipt>
 *   buildReceipt(envelope, publicKeyB64[, opts])→ Receipt
 *   downloadReceipt(receipt, filename?)         → void   (browser only)
 *
 * ``Receipt`` и ``ReceiptVerification`` — plain objects (не классы),
 * чтобы они сериализовались один-в-один и проходили через postMessage /
 * worker-ы без ограничений cloneable.
 *
 * @module trustchain/receipt
 */

/* eslint-env browser, node */

// Универсальный доступ к WebCrypto.  В браузере — `crypto.subtle`,
// в Node 18+ — тоже `globalThis.crypto.subtle` (после node:crypto.webcrypto,
// который Node экспонирует как глобал начиная с 19).  Явно падаем, если
// runtime не умеет Ed25519 — silent false negatives хуже честной ошибки.
function _subtle() {
  const c = (typeof globalThis !== 'undefined' && globalThis.crypto) || null;
  if (!c || !c.subtle) {
    throw new Error(
      'WebCrypto (crypto.subtle) not available. TrustChain receipt ' +
      'verification requires Node ≥ 19 or a browser with Ed25519 support.'
    );
  }
  return c.subtle;
}

function _b64decode(s) {
  if (typeof atob === 'function') {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  // Node fallback
  return new Uint8Array(Buffer.from(s, 'base64'));
}

/**
 * Canonical JSON (UTF-8 string) ≡ Python ``json.dumps(obj, sort_keys=True,
 * separators=(",", ":"))``.
 *
 * Not a generic JCS implementation — just the narrow subset TrustChain uses:
 * objects with sorted string keys, arrays, primitives.  Keep it simple so
 * we can audit byte-for-byte parity with the Python side.
 *
 * @param {unknown} x
 * @returns {string}
 */
export function canonicalize(x) {
  if (x === null || typeof x !== 'object') return JSON.stringify(x);
  if (Array.isArray(x)) return '[' + x.map(canonicalize).join(',') + ']';
  const keys = Object.keys(x).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(x[k])).join(',') + '}';
}

/**
 * Rebuild the byte-sequence covered by the Ed25519 signature, mirroring
 * ``trustchain.v2.signer._build_canonical_data``.
 *
 * Do not reorder fields / change nullability semantics here without
 * updating the Python side in lockstep — otherwise every receipt minted
 * by current Python signers breaks.
 *
 * @param {Record<string, any>} env
 * @returns {Uint8Array}
 */
export function buildCanonicalEnvelope(env) {
  const obj = {
    tool_id: env.tool_id ?? null,
    data: env.data ?? null,
    timestamp: env.timestamp ?? null,
    nonce: env.nonce ?? null,
    parent_signature: env.parent_signature ?? null,
  };
  if (env.metadata    !== undefined && env.metadata    !== null) obj.metadata    = env.metadata;
  if (env.certificate !== undefined && env.certificate !== null) obj.certificate = env.certificate;
  if (env.tsa_proof   !== undefined && env.tsa_proof   !== null) obj.tsa_proof   = env.tsa_proof;
  return new TextEncoder().encode(canonicalize(obj));
}

/**
 * @typedef {Object} ReceiptVerification
 * @property {boolean}       valid
 * @property {boolean}       signature_ok
 * @property {boolean|null}  identity_ok
 * @property {boolean|null}  witnesses_ok
 * @property {string[]}      errors
 * @property {string[]}      warnings
 */

/**
 * Verify a TrustChain receipt in-process.  Signature is checked
 * cryptographically; identity and witness presence get a soft PEM shape
 * check only — full PKIX/CRL validation requires the server-side
 * ``tc-verify --strict``.
 *
 * @param {Record<string, any>} receipt
 * @param {Object} [opts]
 * @param {string} [opts.expectedPublicKeyB64] — reject unless ``key.public_key_b64`` matches.
 * @param {number} [opts.maxAgeSeconds]        — reject envelopes older than this.
 * @returns {Promise<ReceiptVerification>}
 */
export async function verifyReceipt(receipt, opts = {}) {
  const errors = [];
  const warnings = [];

  if (!receipt || typeof receipt !== 'object') {
    return _failFast(errors, 'receipt is not an object');
  }
  if (receipt.format !== 'tcreceipt') {
    errors.push(`format != "tcreceipt" (got ${JSON.stringify(receipt.format)})`);
  }
  if (receipt.version !== 1) {
    errors.push(`unsupported version: ${receipt.version}`);
  }
  const pk = receipt.key && receipt.key.public_key_b64;
  if (!pk) errors.push('key.public_key_b64 missing');
  if (errors.length) return _failFast(errors);

  if (opts.expectedPublicKeyB64 && opts.expectedPublicKeyB64 !== pk) {
    errors.push('public_key_b64 pinning failed — receipt was signed by a different key');
  }

  let signatureOk = false;
  try {
    const key = await _subtle().importKey(
      'raw', _b64decode(pk), { name: 'Ed25519' }, true, ['verify']
    );
    const msg = buildCanonicalEnvelope(receipt.envelope || {});
    const sig = _b64decode((receipt.envelope && receipt.envelope.signature) || '');
    signatureOk = await _subtle().verify('Ed25519', key, sig, msg);
    if (!signatureOk) errors.push('Ed25519 signature does not match the envelope');
  } catch (e) {
    errors.push('crypto error: ' + (e && e.message ? e.message : String(e)));
  }

  if (typeof opts.maxAgeSeconds === 'number' && receipt.envelope) {
    const ts = receipt.envelope.timestamp;
    if (typeof ts === 'number') {
      const age = Date.now() / 1000 - ts;
      if (age > opts.maxAgeSeconds) {
        errors.push(`envelope is ${age.toFixed(0)}s old, maxAgeSeconds=${opts.maxAgeSeconds}`);
      }
    }
  }

  let identityOk = null;
  if (receipt.identity) {
    const chain = receipt.identity.cert_chain_pem;
    if (!Array.isArray(chain) || chain.length === 0) {
      identityOk = false;
      warnings.push('identity present but cert_chain_pem is empty');
    } else if (!chain.every(p => typeof p === 'string' && p.includes('BEGIN CERTIFICATE'))) {
      identityOk = false;
      errors.push('identity.cert_chain_pem contains non-PEM entries');
    } else {
      identityOk = true;
    }
  }

  let witnessesOk = null;
  if (Array.isArray(receipt.witnesses)) {
    witnessesOk = receipt.witnesses.length > 0;
    warnings.push(
      'witness signatures not verified in-browser — run `tc receipt verify` for cryptographic witness check'
    );
  }

  const valid = signatureOk
    && identityOk !== false
    && witnessesOk !== false
    && errors.length === 0;

  return { valid, signature_ok: signatureOk, identity_ok: identityOk, witnesses_ok: witnessesOk, errors, warnings };
}

function _failFast(errors, extra) {
  if (extra) errors.push(extra);
  return {
    valid: false,
    signature_ok: false,
    identity_ok: null,
    witnesses_ok: null,
    errors,
    warnings: [],
  };
}

/**
 * Resolve heterogeneous inputs (File, Blob, string, URL, plain object) into
 * a receipt object.  Does NOT verify — just parses and sanity-checks shape.
 *
 * @param {File|Blob|string|URL|Object} input
 * @returns {Promise<Object>}
 */
export async function loadReceipt(input) {
  if (!input) throw new Error('loadReceipt: input is empty');
  if (typeof input === 'object' && !(input instanceof Blob) && !(input instanceof URL)) {
    return _validateShape(input);
  }
  if (input instanceof Blob || (typeof File !== 'undefined' && input instanceof File)) {
    return _validateShape(JSON.parse(await input.text()));
  }
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      return _validateShape(JSON.parse(trimmed));
    }
    // Treat as URL (fetch).
    const resp = await fetch(trimmed);
    if (!resp.ok) throw new Error(`loadReceipt: fetch ${trimmed} → ${resp.status}`);
    return _validateShape(await resp.json());
  }
  if (input instanceof URL) {
    const resp = await fetch(input.toString());
    if (!resp.ok) throw new Error(`loadReceipt: fetch ${input} → ${resp.status}`);
    return _validateShape(await resp.json());
  }
  throw new Error('loadReceipt: unsupported input type');
}

function _validateShape(doc) {
  if (!doc || typeof doc !== 'object') {
    throw new Error('Not a TrustChain receipt: top-level is not an object');
  }
  if (doc.format !== 'tcreceipt') {
    throw new Error(`Not a TrustChain receipt: format=${JSON.stringify(doc.format)}`);
  }
  return doc;
}

/**
 * Assemble a receipt from an existing envelope + public key.  Mirrors
 * Python ``trustchain.build_receipt`` so receipts produced in JS roundtrip
 * through the Python CLI and vice-versa.
 *
 * @param {Object} envelope        — SignedResponse.to_dict()-shaped object
 * @param {string} publicKeyB64
 * @param {Object} [opts]
 * @returns {Object}
 */
export function buildReceipt(envelope, publicKeyB64, opts = {}) {
  const env = envelope && typeof envelope.toDict === 'function' ? envelope.toDict() : { ...envelope };
  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  return {
    format: 'tcreceipt',
    version: 1,
    issued_at: now,
    envelope: env,
    key: {
      algorithm: opts.algorithm || 'ed25519',
      key_id: opts.keyId ?? null,
      public_key_b64: publicKeyB64,
    },
    identity: opts.identity || null,
    witnesses: opts.witnesses || null,
    summary: _deriveSummary(env),
  };
}

function _deriveSummary(env) {
  const ts = env.timestamp;
  let ts_iso = null;
  if (typeof ts === 'number' && Number.isFinite(ts)) {
    try { ts_iso = new Date(ts * 1000).toISOString().replace(/\.\d+Z$/, 'Z'); }
    catch (_) { /* ignore */ }
  }
  const sig = String(env.signature || '');
  return {
    tool_id: env.tool_id ?? null,
    timestamp_iso: ts_iso,
    signature_short: sig.length > 8 ? sig.slice(0, 8) + '…' : sig,
  };
}

/**
 * Trigger a browser download for the given receipt.  No-op outside browsers.
 *
 * @param {Object} receipt
 * @param {string} [filename]  — defaults to ``<tool_id>-<shortsig>.tcreceipt``
 */
export function downloadReceipt(receipt, filename) {
  if (typeof document === 'undefined' || typeof URL === 'undefined' || typeof Blob === 'undefined') {
    return;  // Node / SSR — nothing to do.
  }
  const env = receipt.envelope || {};
  const sig = String(env.signature || '').slice(0, 8) || 'receipt';
  const name = filename || `${env.tool_id || 'trustchain'}-${sig}.tcreceipt`;
  const blob = new Blob([JSON.stringify(receipt, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  requestAnimationFrame(() => {
    a.remove();
    URL.revokeObjectURL(url);
  });
}
