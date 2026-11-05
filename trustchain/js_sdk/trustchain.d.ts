/**
 * TypeScript definitions for TrustChain JavaScript SDK
 */

export interface TrustChainOptions {
    timeout?: number;
    retries?: number;
    autoVerify?: boolean;
}

export interface ClientStats {
    totalCalls: number;
    successfulCalls: number;
    failedCalls: number;
    verificationSuccess: number;
    verificationFailed: number;
    successRate: string;
    verificationRate: string;
}

export interface ServerStats {
    total_tools: number;
    total_calls: number;
    cache_size: number;
    uptime_seconds: number;
    version: string;
}

export interface ToolInfo {
    name: string;
    description: string;
    is_async: boolean;
}

export interface HealthStatus {
    status: string;
    version: string;
    timestamp: number;
}

export interface WebSocketMessage {
    type: string;
    [key: string]: any;
}

export declare class TrustChainError extends Error {
    code: string | null;
    details: any;
    
    constructor(message: string, code?: string | null, details?: any);
}

export declare class VerificationError extends TrustChainError {
    signature: string | null;
    
    constructor(message: string, signature?: string | null);
}

export declare class SignedResponse {
    tool_id: string;
    data: any;
    signature: string;
    signature_id: string;
    timestamp: number;
    nonce: string | null;
    is_verified: boolean;
    /** Preserved on decoding; declared profiles require the Python verifier. */
    canon?: string | null;
    
    constructor(data: {
        tool_id: string;
        data: any;
        signature: string;
        signature_id?: string;
        timestamp?: number;
        nonce?: string | null;
        is_verified?: boolean;
        canon?: string | null;
    });
    
    toDict(): {
        tool_id: string;
        data: any;
        signature: string;
        signature_id: string;
        timestamp: number;
        nonce: string | null;
        is_verified: boolean;
        canon?: string | null;
    };
    
    getSignaturePreview(): string;
    getFormattedTimestamp(): string;
}

export declare class TrustChainClient {
    baseUrl: string;
    options: TrustChainOptions;
    websocket: WebSocket | null;
    stats: ClientStats;
    
    constructor(baseUrl?: string, options?: TrustChainOptions);
    
    callTool(toolName: string, parameters?: Record<string, any>, nonce?: string | null): Promise<SignedResponse>;
    verify(signedResponse: SignedResponse): Promise<boolean>;
    getTools(): Promise<ToolInfo[]>;
    getServerStats(): Promise<ServerStats>;
    getClientStats(): ClientStats;
    healthCheck(): Promise<HealthStatus>;
    
    connectWebSocket(onMessage?: ((message: WebSocketMessage) => void) | null): Promise<void>;
    disconnectWebSocket(): void;
    onWebSocketMessage(id: string, callback: (message: WebSocketMessage) => void): void;
    offWebSocketMessage(id: string): void;
}

export declare const TrustChainUtils: {
    generateNonce(): string;
    formatExecutionTime(ms: number): string;
    validateToolName(name: string): boolean;
};

// Default export for CommonJS compatibility
declare const _default: {
    TrustChainClient: typeof TrustChainClient;
    SignedResponse: typeof SignedResponse;
    TrustChainError: typeof TrustChainError;
    VerificationError: typeof VerificationError;
    TrustChainUtils: typeof TrustChainUtils;
};

export default _default; 