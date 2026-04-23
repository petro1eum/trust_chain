/**
 * TrustChain React Integration
 * 
 * Provides React hooks and components for TrustChain verification.
 * 
 * @version 1.0.0
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

// ============================================================================
// Context
// ============================================================================

const TrustChainContext = createContext(null);

/**
 * TrustChain Provider - Wrap your app to provide verification context.
 * 
 * @example
 * <TrustChainProvider publicKeyUrl="/api/trustchain/public-key">
 *   <App />
 * </TrustChainProvider>
 */
export function TrustChainProvider({ children, publicKey, publicKeyUrl, verifier }) {
    const [trustChainVerifier, setVerifier] = useState(verifier || null);
    const [isReady, setIsReady] = useState(!!verifier);
    const [error, setError] = useState(null);

    useEffect(() => {
        if (verifier) {
            setVerifier(verifier);
            setIsReady(true);
            return;
        }

        // Initialize TrustChainVerifier
        const initVerifier = async () => {
            try {
                // Import from trustchain.js (assumes it's available globally or bundled)
                const { TrustChainVerifier } = window.TrustChain || await import('./trustchain.js');

                const v = new TrustChainVerifier({ publicKey, publicKeyUrl });
                await v.initialize();

                setVerifier(v);
                setIsReady(true);
            } catch (err) {
                setError(err.message);
                console.error('TrustChain initialization failed:', err);
            }
        };

        initVerifier();
    }, [publicKey, publicKeyUrl, verifier]);

    const value = {
        verifier: trustChainVerifier,
        isReady,
        error,
    };

    return (
        <TrustChainContext.Provider value={value}>
            {children}
        </TrustChainContext.Provider>
    );
}

// ============================================================================
// Hooks
// ============================================================================

/**
 * Hook to access TrustChain context.
 */
export function useTrustChainContext() {
    const context = useContext(TrustChainContext);
    if (!context) {
        throw new Error('useTrustChainContext must be used within TrustChainProvider');
    }
    return context;
}

/**
 * Hook to verify a signed response.
 * 
 * @example
 * function ToolResult({ response }) {
 *   const { isVerified, isLoading, error, verify } = useTrustChain(response);
 *   
 *   return (
 *     <div>
 *       {isLoading && <Spinner />}
 *       {isVerified && <VerifiedBadge />}
 *       {error && <ErrorBadge message={error} />}
 *     </div>
 *   );
 * }
 */
export function useTrustChain(signedResponse, options = {}) {
    const { verifier, isReady } = useTrustChainContext();
    const [isVerified, setIsVerified] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState(null);

    const { autoVerify = true } = options;

    const verify = useCallback(async () => {
        if (!verifier || !signedResponse) {
            return null;
        }

        setIsLoading(true);
        setError(null);

        try {
            const result = await verifier.verify(signedResponse);
            setIsVerified(result);
            return result;
        } catch (err) {
            setError(err.message);
            setIsVerified(false);
            return false;
        } finally {
            setIsLoading(false);
        }
    }, [verifier, signedResponse]);

    // Auto-verify when response changes
    useEffect(() => {
        if (autoVerify && isReady && signedResponse) {
            verify();
        }
    }, [autoVerify, isReady, signedResponse, verify]);

    return {
        isVerified,
        isLoading,
        error,
        verify,
        isReady,
    };
}

/**
 * Hook to verify a chain of responses.
 * 
 * @example
 * function ChainStatus({ chain }) {
 *   const { isValid, invalidIndex } = useTrustChainVerify(chain);
 *   return isValid ? <ValidChain /> : <BrokenChain index={invalidIndex} />;
 * }
 */
export function useTrustChainVerify(chain, options = {}) {
    const { verifier, isReady } = useTrustChainContext();
    const [isValid, setIsValid] = useState(null);
    const [invalidIndex, setInvalidIndex] = useState(null);
    const [isLoading, setIsLoading] = useState(false);

    const { autoVerify = true } = options;

    const verifyChain = useCallback(async () => {
        if (!verifier || !chain || chain.length === 0) {
            return null;
        }

        setIsLoading(true);

        try {
            const result = await verifier.verifyChain(chain);
            setIsValid(result);
            setInvalidIndex(null);
            return result;
        } catch (err) {
            setIsValid(false);
            return false;
        } finally {
            setIsLoading(false);
        }
    }, [verifier, chain]);

    useEffect(() => {
        if (autoVerify && isReady && chain) {
            verifyChain();
        }
    }, [autoVerify, isReady, chain, verifyChain]);

    return {
        isValid,
        invalidIndex,
        isLoading,
        verifyChain,
    };
}

// ============================================================================
// Components
// ============================================================================

/**
 * Badge component showing verification status.
 * 
 * @example
 * <VerifiedBadge status="verified" />
 * <VerifiedBadge status="failed" />
 * <VerifiedBadge status="loading" />
 */
export function VerifiedBadge({
    status = 'unknown',
    size = 'md',
    showLabel = true,
    className = ''
}) {
    const sizeClasses = {
        sm: { icon: '14px', font: '12px', padding: '2px 6px' },
        md: { icon: '16px', font: '14px', padding: '4px 8px' },
        lg: { icon: '20px', font: '16px', padding: '6px 12px' },
    };

    const statusConfig = {
        verified: {
            icon: '✓',
            label: 'Verified',
            color: '#10b981',
            bg: '#d1fae5',
        },
        failed: {
            icon: '✗',
            label: 'Invalid',
            color: '#ef4444',
            bg: '#fee2e2',
        },
        loading: {
            icon: '⟳',
            label: 'Verifying...',
            color: '#6b7280',
            bg: '#f3f4f6',
        },
        unknown: {
            icon: '?',
            label: 'Unknown',
            color: '#9ca3af',
            bg: '#f9fafb',
        },
    };

    const config = statusConfig[status] || statusConfig.unknown;
    const sizing = sizeClasses[size] || sizeClasses.md;

    const style = {
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        padding: sizing.padding,
        borderRadius: '9999px',
        fontSize: sizing.font,
        fontWeight: 500,
        color: config.color,
        backgroundColor: config.bg,
        border: `1px solid ${config.color}20`,
    };

    const iconStyle = {
        fontSize: sizing.icon,
        lineHeight: 1,
    };

    return (
        <span style={style} className={className}>
            <span style={iconStyle}>{config.icon}</span>
            {showLabel && <span>{config.label}</span>}
        </span>
    );
}

/**
 * Component that auto-verifies and shows badge.
 * 
 * @example
 * <VerifiedResponse response={signedResponse} />
 */
export function VerifiedResponse({ response, size = 'md', showLabel = true }) {
    const { isVerified, isLoading } = useTrustChain(response);

    let status = 'unknown';
    if (isLoading) status = 'loading';
    else if (isVerified === true) status = 'verified';
    else if (isVerified === false) status = 'failed';

    return <VerifiedBadge status={status} size={size} showLabel={showLabel} />;
}

/**
 * Component showing certificate info from signed response.
 * 
 * @example
 * <CertificateInfo response={signedResponse} />
 */
export function CertificateInfo({ response, className = '' }) {
    if (!response?.certificate) {
        return null;
    }

    const cert = response.certificate;

    const style = {
        display: 'flex',
        flexDirection: 'column',
        gap: '4px',
        padding: '8px 12px',
        backgroundColor: '#f8fafc',
        borderRadius: '8px',
        fontSize: '13px',
        border: '1px solid #e2e8f0',
    };

    const labelStyle = {
        color: '#64748b',
        fontSize: '11px',
        textTransform: 'uppercase',
        letterSpacing: '0.5px',
    };

    const valueStyle = {
        color: '#1e293b',
        fontWeight: 500,
    };

    return (
        <div style={style} className={className}>
            {cert.owner && (
                <div>
                    <span style={labelStyle}>Signed by</span>
                    <div style={valueStyle}>{cert.owner}</div>
                </div>
            )}
            {cert.organization && (
                <div>
                    <span style={labelStyle}>Organization</span>
                    <div style={valueStyle}>{cert.organization}</div>
                </div>
            )}
            {cert.tier && (
                <div>
                    <span style={labelStyle}>Tier</span>
                    <div style={valueStyle}>{cert.tier}</div>
                </div>
            )}
        </div>
    );
}

// ============================================================================
// Receipt support — portable .tcreceipt objects (see receipt.js)
// ============================================================================

import {
    loadReceipt as _loadReceipt,
    verifyReceipt as _verifyReceipt,
    buildReceipt as _buildReceipt,
    downloadReceipt as _downloadReceipt,
} from './receipt.mjs';

export {
    buildReceipt,
    canonicalize,
    buildCanonicalEnvelope,
    loadReceipt,
    verifyReceipt,
    downloadReceipt,
} from './receipt.mjs';

/**
 * Hook that loads + verifies a TrustChain receipt.
 *
 * Accepts heterogeneous sources: parsed receipt object, JSON string, URL,
 * File, or Blob.  Re-runs verification when ``source`` changes.  Safe to
 * render inside drop-zones — loading/error states are surfaced explicitly.
 *
 * @example
 *   const { receipt, verification, isLoading, error, download, refresh }
 *     = useReceipt(file, { expectedPublicKeyB64, maxAgeSeconds: 3600 });
 *
 * @param {File|Blob|string|URL|Object|null} source
 * @param {Object} [options]
 * @param {string} [options.expectedPublicKeyB64]
 * @param {number} [options.maxAgeSeconds]
 * @returns {{
 *   receipt: Object|null,
 *   verification: import('./receipt.mjs').ReceiptVerification|null,
 *   isLoading: boolean,
 *   error: string|null,
 *   download: (filename?: string) => void,
 *   refresh: () => Promise<void>,
 * }}
 */
export function useReceipt(source, options = {}) {
    const [receipt, setReceipt]           = useState(null);
    const [verification, setVerification] = useState(null);
    const [isLoading, setIsLoading]       = useState(false);
    const [error, setError]               = useState(null);

    const { expectedPublicKeyB64, maxAgeSeconds } = options;

    const run = useCallback(async () => {
        if (source == null) {
            setReceipt(null);
            setVerification(null);
            setError(null);
            return;
        }
        setIsLoading(true);
        setError(null);
        try {
            const r = await _loadReceipt(source);
            setReceipt(r);
            const v = await _verifyReceipt(r, { expectedPublicKeyB64, maxAgeSeconds });
            setVerification(v);
        } catch (e) {
            setReceipt(null);
            setVerification(null);
            setError(e && e.message ? e.message : String(e));
        } finally {
            setIsLoading(false);
        }
    }, [source, expectedPublicKeyB64, maxAgeSeconds]);

    useEffect(() => { run(); }, [run]);

    const download = useCallback((filename) => {
        if (receipt) _downloadReceipt(receipt, filename);
    }, [receipt]);

    return { receipt, verification, isLoading, error, download, refresh: run };
}

/**
 * Headless-first receipt component.
 *
 * * If ``children`` is a function, it's called with the full hook state
 *   — caller owns rendering. This is the main integration point.
 * * Otherwise a minimal dark-on-light default card is rendered.  The
 *   default is deliberately plain so product UIs re-skin it.
 *
 * @example
 *   // Fully headless
 *   <TrustReceipt source={file}>
 *     {({ verification, download }) => ...}
 *   </TrustReceipt>
 *
 *   // Default renderer
 *   <TrustReceipt source={file} />
 */
export function TrustReceipt({ source, expectedPublicKeyB64, maxAgeSeconds, children, className = '' }) {
    const state = useReceipt(source, { expectedPublicKeyB64, maxAgeSeconds });

    if (typeof children === 'function') return children(state);

    const { receipt, verification, isLoading, error, download } = state;

    const rootStyle = {
        border: '1px solid #d6dae1',
        borderRadius: 12,
        padding: 16,
        fontFamily: 'system-ui, -apple-system, sans-serif',
        background: '#fff',
        color: '#1a1d21',
        maxWidth: 480,
    };
    const mono = {
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
        fontSize: 12,
        wordBreak: 'break-all',
    };
    const row = { display: 'flex', justifyContent: 'space-between', gap: 8, margin: '6px 0' };
    const label = { color: '#5c6673', fontSize: 12 };

    if (isLoading) {
        return <div style={rootStyle} className={className}>Verifying receipt…</div>;
    }
    if (error) {
        return (
            <div style={{ ...rootStyle, borderColor: '#ef4b5c' }} className={className}>
                <strong>Receipt error</strong>
                <div style={mono}>{error}</div>
            </div>
        );
    }
    if (!receipt || !verification) return null;

    const status = verification.valid
        ? { label: 'VALID',    color: '#28c76f' }
        : verification.signature_ok
            ? { label: 'DEGRADED', color: '#f0b84b' }
            : { label: 'INVALID',  color: '#ef4b5c' };

    return (
        <div
            style={{ ...rootStyle, borderColor: status.color }}
            className={className}
            data-tc-verdict={status.label.toLowerCase()}
        >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{
                    width: 10, height: 10, borderRadius: '50%',
                    background: status.color,
                }} />
                <strong>Receipt {status.label}</strong>
            </div>
            <div style={row}>
                <span style={label}>tool_id</span>
                <span style={mono}>{receipt.envelope?.tool_id ?? '—'}</span>
            </div>
            <div style={row}>
                <span style={label}>timestamp</span>
                <span style={mono}>{receipt.summary?.timestamp_iso ?? '—'}</span>
            </div>
            <div style={row}>
                <span style={label}>key_id</span>
                <span style={mono}>{receipt.key?.key_id ?? '—'}</span>
            </div>
            <div style={row}>
                <span style={label}>signature</span>
                <span style={mono}>{receipt.summary?.signature_short ?? '—'}</span>
            </div>
            {verification.errors.length > 0 && (
                <ul style={{ margin: '8px 0 0', paddingLeft: 18, color: '#ef4b5c' }}>
                    {verification.errors.map((e, i) => <li key={i} style={mono}>{e}</li>)}
                </ul>
            )}
            <button
                type="button"
                onClick={() => download()}
                style={{
                    marginTop: 12, padding: '6px 10px',
                    border: '1px solid #d6dae1', background: 'transparent',
                    borderRadius: 6, cursor: 'pointer', fontSize: 13,
                }}
            >Download .tcreceipt</button>
        </div>
    );
}

// ============================================================================
// Exports
// ============================================================================

export default {
    TrustChainProvider,
    useTrustChain,
    useTrustChainContext,
    useTrustChainVerify,
    useReceipt,
    VerifiedBadge,
    VerifiedResponse,
    CertificateInfo,
    TrustReceipt,
};
