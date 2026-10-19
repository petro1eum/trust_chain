// F09: a verifier must never silently reinterpret a declared signing profile.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { buildCanonicalEnvelope, buildReceipt, verifyReceipt } from '../receipt.mjs';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
const { SignedResponse, TrustChainVerifier } = createRequire(import.meta.url)('../trustchain.js');

// Exercise the functions shipped in the standalone HTML, not a copied test implementation.
const html = readFileSync(new URL('../../../examples/verify.html', import.meta.url), 'utf8');
const start = html.indexOf('function canonicalize(');
const end = html.indexOf('// ------------------------------------------------------------------ verification', start);
assert.ok(start > 0 && end > start);
const browserEnvelope = new Function('TextEncoder',
  html.slice(start, end) + '\nreturn buildCanonicalEnvelope;')(TextEncoder);

async function legacyFixture() {
  const keys = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicKey = Buffer.from(await webcrypto.subtle.exportKey('raw', keys.publicKey)).toString('base64');
  const envelope = { tool_id: 'fixture', data: { value: 1 }, timestamp: 1700000000.5,
    nonce: 'fixture-only', parent_signature: null };
  const signature = await webcrypto.subtle.sign('Ed25519', keys.privateKey, buildCanonicalEnvelope(envelope));
  envelope.signature = Buffer.from(signature).toString('base64');
  return { envelope, publicKey };
}

for (const canon of [undefined, null]) {
  test(`unmarked legacy receipts keep their existing bytes (${canon})`, async () => {
    const { envelope, publicKey } = await legacyFixture();
    const expected = new TextEncoder().encode(
      '{"data":{"value":1},"nonce":"fixture-only","parent_signature":null,"timestamp":1700000000.5,"tool_id":"fixture"}');
    envelope.canon = canon;
    assert.deepEqual(buildCanonicalEnvelope(envelope), expected);
    assert.deepEqual(browserEnvelope(envelope), expected);
    assert.equal((await verifyReceipt(buildReceipt(envelope, publicKey))).valid, true);
    const verifier = new TrustChainVerifier({ publicKey });
    assert.equal(await verifier.verify(envelope), true);
    assert.equal(await verifier.verify(new SignedResponse(envelope)), true);
  });
}

for (const canon of ['jcs', 'json-sort-keys-minified', 'unknown-profile', '']) {
  test(`declared profile cannot be ignored or dropped: ${JSON.stringify(canon)}`, async () => {
    const { envelope, publicKey } = await legacyFixture();
    envelope.canon = canon; // Re-label an existing signature, without signing again.
    const receipt = await verifyReceipt(buildReceipt(envelope, publicKey));
    assert.equal(receipt.valid, false);
    assert.equal(receipt.signature_ok, false);
    assert.match(receipt.errors.join('; '), /unsupported canonicalization profile/i);
    assert.throws(() => buildCanonicalEnvelope(envelope), /unsupported canonicalization profile/i);
    assert.throws(() => browserEnvelope(envelope), /unsupported canonicalization profile/i);

    const verifier = new TrustChainVerifier({ publicKey });
    assert.equal(await verifier.verify(envelope), false);
    const decoded = new SignedResponse(envelope);
    assert.equal(decoded.toDict().canon, canon); // Decoding must not erase a signed selector.
    assert.equal(await verifier.verify(decoded), false);
  });
}
