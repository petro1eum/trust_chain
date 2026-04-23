/**
 * TypeScript definitions for `trustchain-js/receipt`.
 *
 * См. receipt.mjs — формат и контракты описаны там.
 */

export interface ReceiptVerification {
    valid: boolean;
    signature_ok: boolean;
    identity_ok: boolean | null;
    witnesses_ok: boolean | null;
    errors: string[];
    warnings: string[];
}

export interface ReceiptEnvelope {
    tool_id: string;
    data: unknown;
    signature: string;
    signature_id?: string;
    timestamp: number;
    nonce?: string | null;
    parent_signature?: string | null;
    metadata?: Record<string, unknown> | null;
    certificate?: Record<string, unknown> | null;
    tsa_proof?: Record<string, unknown> | null;
}

export interface ReceiptIdentity {
    subject_cn?: string;
    issuer_cn?: string;
    cert_chain_pem?: string[];
}

export interface Receipt {
    format: 'tcreceipt';
    version: 1;
    issued_at: string;
    envelope: ReceiptEnvelope;
    key: {
        algorithm: string;
        key_id: string | null;
        public_key_b64: string;
    };
    identity?: ReceiptIdentity | null;
    witnesses?: Array<Record<string, unknown>> | null;
    summary?: {
        tool_id: string | null;
        timestamp_iso: string | null;
        signature_short: string;
    };
}

export interface VerifyOptions {
    expectedPublicKeyB64?: string;
    maxAgeSeconds?: number;
}

export interface BuildOptions {
    algorithm?: string;
    keyId?: string | null;
    identity?: ReceiptIdentity | null;
    witnesses?: Array<Record<string, unknown>> | null;
}

export function canonicalize(value: unknown): string;
export function buildCanonicalEnvelope(envelope: ReceiptEnvelope): Uint8Array;
export function verifyReceipt(
    receipt: Receipt,
    opts?: VerifyOptions,
): Promise<ReceiptVerification>;
export function loadReceipt(input: Blob | File | string | URL | Receipt): Promise<Receipt>;
export function buildReceipt(
    envelope: ReceiptEnvelope,
    publicKeyB64: string,
    opts?: BuildOptions,
): Receipt;
export function downloadReceipt(receipt: Receipt, filename?: string): void;
