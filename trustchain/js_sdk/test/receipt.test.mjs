/**
 * Node built-in test-runner suite for the receipt module.
 *
 * Зачем Node built-in, а не Jest/Vitest: receipt.mjs — zero-dependency ESM.
 * Тянуть dev-toolchain ради 20 строк тестов — overkill. Этот файл запускается
 * через ``node --test test/`` (см. package.json → scripts.test).
 *
 * Контракт, который проверяем:
 *
 *   1. canonicalize() сортирует ключи и матчит JSON, который подписал Python.
 *   2. verifyReceipt() пропускает honest receipt.
 *   3. Tamper (изменение data/timestamp/signature) → ``valid === false``.
 *   4. buildReceipt()/loadReceipt() round-trip через JSON без потерь.
 *   5. Pinning: несовпадение expectedPublicKeyB64 → invalid.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

import {
    canonicalize,
    buildCanonicalEnvelope,
    buildReceipt,
    loadReceipt,
    verifyReceipt,
} from '../receipt.mjs';

// ----- helpers ----------------------------------------------------------- //

// Node exposes webcrypto as globalThis.crypto only from v19+.  Ensure it
// is there for older CI nodes.  If this shim isn't needed (Node ≥ 19),
// the assignment is harmless.
if (!globalThis.crypto) globalThis.crypto = webcrypto;

async function mintSigned({ tool_id = 'calc', data = { x: 1 } } = {}) {
    const kp = await webcrypto.subtle.generateKey(
        { name: 'Ed25519' }, true, ['sign', 'verify']
    );
    const raw = await webcrypto.subtle.exportKey('raw', kp.publicKey);
    const pk = Buffer.from(raw).toString('base64');

    const envelope = {
        tool_id,
        data,
        timestamp: 1700000000,
        nonce: 'fixed-nonce-for-test',
        parent_signature: null,
    };
    const canon = buildCanonicalEnvelope(envelope);
    const sig = await webcrypto.subtle.sign('Ed25519', kp.privateKey, canon);
    envelope.signature = Buffer.from(sig).toString('base64');
    envelope.signature_id = 'sig-0001';
    return { envelope, publicKeyB64: pk };
}

// ----- canonicalization -------------------------------------------------- //

test('canonicalize sorts object keys deterministically', () => {
    const a = canonicalize({ b: 2, a: 1, c: { y: 1, x: 2 } });
    assert.equal(a, '{"a":1,"b":2,"c":{"x":2,"y":1}}');
});

test('canonicalize preserves array ordering', () => {
    assert.equal(canonicalize([3, 1, 2]), '[3,1,2]');
});

test('canonicalize nulls and primitives', () => {
    assert.equal(canonicalize(null), 'null');
    assert.equal(canonicalize('hi'), '"hi"');
    assert.equal(canonicalize(42), '42');
});

test('buildCanonicalEnvelope omits null optional fields', () => {
    const bytes = buildCanonicalEnvelope({
        tool_id: 't', data: {}, timestamp: 1, nonce: 'n', parent_signature: null,
        metadata: null,  // must be dropped to match Python
        certificate: null,
        tsa_proof: null,
    });
    const json = new TextDecoder().decode(bytes);
    assert.ok(!json.includes('metadata'));
    assert.ok(!json.includes('certificate'));
    assert.ok(!json.includes('tsa_proof'));
});

// ----- happy path -------------------------------------------------------- //

test('roundtrip: build → load → verify is valid', async () => {
    const { envelope, publicKeyB64 } = await mintSigned();
    const receipt = buildReceipt(envelope, publicKeyB64, { keyId: 'k1' });
    assert.equal(receipt.format, 'tcreceipt');
    assert.equal(receipt.version, 1);

    const roundtripped = await loadReceipt(JSON.stringify(receipt));
    const v = await verifyReceipt(roundtripped);
    assert.equal(v.valid, true, v.errors.join('; '));
    assert.equal(v.signature_ok, true);
});

test('receipt summary is derived from envelope', async () => {
    const { envelope, publicKeyB64 } = await mintSigned({ tool_id: 'weather' });
    const r = buildReceipt(envelope, publicKeyB64);
    assert.equal(r.summary.tool_id, 'weather');
    assert.ok(r.summary.timestamp_iso.startsWith('2023-'));
    assert.ok(r.summary.signature_short.endsWith('…'));
});

// ----- tamper-evidence --------------------------------------------------- //

test('tamper on data breaks signature', async () => {
    const { envelope, publicKeyB64 } = await mintSigned();
    const receipt = buildReceipt(envelope, publicKeyB64);
    receipt.envelope.data = { x: 999 };  // saboteur edit
    const v = await verifyReceipt(receipt);
    assert.equal(v.valid, false);
    assert.equal(v.signature_ok, false);
});

test('tamper on timestamp breaks signature', async () => {
    const { envelope, publicKeyB64 } = await mintSigned();
    const receipt = buildReceipt(envelope, publicKeyB64);
    receipt.envelope.timestamp += 1;
    const v = await verifyReceipt(receipt);
    assert.equal(v.valid, false);
});

test('truncated signature fails', async () => {
    const { envelope, publicKeyB64 } = await mintSigned();
    const receipt = buildReceipt(envelope, publicKeyB64);
    receipt.envelope.signature = receipt.envelope.signature.slice(0, 20);
    const v = await verifyReceipt(receipt);
    assert.equal(v.signature_ok, false);
});

// ----- pinning ----------------------------------------------------------- //

test('expectedPublicKeyB64 mismatch is invalid', async () => {
    const { envelope, publicKeyB64 } = await mintSigned();
    const receipt = buildReceipt(envelope, publicKeyB64);
    const v = await verifyReceipt(receipt, { expectedPublicKeyB64: 'DIFFERENT' });
    assert.equal(v.valid, false);
    assert.ok(v.errors.some(e => e.includes('pinning')));
});

test('expectedPublicKeyB64 match passes', async () => {
    const { envelope, publicKeyB64 } = await mintSigned();
    const receipt = buildReceipt(envelope, publicKeyB64);
    const v = await verifyReceipt(receipt, { expectedPublicKeyB64: publicKeyB64 });
    assert.equal(v.valid, true, v.errors.join('; '));
});

// ----- format hardening -------------------------------------------------- //

test('loadReceipt rejects non-tcreceipt JSON', async () => {
    await assert.rejects(
        () => loadReceipt(JSON.stringify({ format: 'other' })),
        /Not a TrustChain receipt/,
    );
});

test('verifyReceipt rejects unsupported version', async () => {
    const { envelope, publicKeyB64 } = await mintSigned();
    const receipt = buildReceipt(envelope, publicKeyB64);
    receipt.version = 999;
    const v = await verifyReceipt(receipt);
    assert.equal(v.valid, false);
    assert.ok(v.errors.some(e => e.toLowerCase().includes('version')));
});
