import { ReactNode } from 'react';

// Types
export interface SignedResponse {
    tool_id: string;
    data: any;
    signature: string;
    signature_id: string;
    timestamp: number;
    nonce?: string;
    parent_signature?: string;
    certificate?: Certificate;
}

export interface Certificate {
    owner?: string;
    organization?: string;
    tier?: 'community' | 'pro' | 'enterprise';
    role?: string;
    issued_by?: string;
    valid_until?: string;
}

export interface TrustChainVerifier {
    verify(response: SignedResponse): Promise<boolean>;
    verifyChain(chain: SignedResponse[]): Promise<boolean>;
    initialize(): Promise<this>;
}

// Context
export interface TrustChainContextValue {
    verifier: TrustChainVerifier | null;
    isReady: boolean;
    error: string | null;
}

// Provider Props
export interface TrustChainProviderProps {
    children: ReactNode;
    publicKey?: string;
    publicKeyUrl?: string;
    verifier?: TrustChainVerifier;
}

// Hook Returns
export interface UseTrustChainResult {
    isVerified: boolean | null;
    isLoading: boolean;
    error: string | null;
    verify: () => Promise<boolean | null>;
    isReady: boolean;
}

export interface UseTrustChainVerifyResult {
    isValid: boolean | null;
    invalidIndex: number | null;
    isLoading: boolean;
    verifyChain: () => Promise<boolean | null>;
}

// Component Props
export interface VerifiedBadgeProps {
    status?: 'verified' | 'failed' | 'loading' | 'unknown';
    size?: 'sm' | 'md' | 'lg';
    showLabel?: boolean;
    className?: string;
}

export interface VerifiedResponseProps {
    response: SignedResponse;
    size?: 'sm' | 'md' | 'lg';
    showLabel?: boolean;
}

export interface CertificateInfoProps {
    response: SignedResponse;
    className?: string;
}

// Provider
export function TrustChainProvider(props: TrustChainProviderProps): JSX.Element;

// Hooks
export function useTrustChainContext(): TrustChainContextValue;
export function useTrustChain(
    signedResponse: SignedResponse | null,
    options?: { autoVerify?: boolean }
): UseTrustChainResult;
export function useTrustChainVerify(
    chain: SignedResponse[] | null,
    options?: { autoVerify?: boolean }
): UseTrustChainVerifyResult;

// Components
export function VerifiedBadge(props: VerifiedBadgeProps): JSX.Element;
export function VerifiedResponse(props: VerifiedResponseProps): JSX.Element;
export function CertificateInfo(props: CertificateInfoProps): JSX.Element | null;

// Default export
declare const _default: {
    TrustChainProvider: typeof TrustChainProvider;
    useTrustChain: typeof useTrustChain;
    useTrustChainContext: typeof useTrustChainContext;
    useTrustChainVerify: typeof useTrustChainVerify;
    VerifiedBadge: typeof VerifiedBadge;
    VerifiedResponse: typeof VerifiedResponse;
    CertificateInfo: typeof CertificateInfo;
};

export default _default;
