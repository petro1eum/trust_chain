/**
 * TrustChain JavaScript SDK
 * 
 * Provides cryptographically verified tool execution for JavaScript/Node.js applications.
 * 
 * @version 2.1.0
 * @author TrustChain Team
 */

class TrustChainError extends Error {
    constructor(message, code = null, details = null) {
        super(message);
        this.name = 'TrustChainError';
        this.code = code;
        this.details = details;
    }
}

class VerificationError extends TrustChainError {
    constructor(message, signature = null) {
        super(message, 'VERIFICATION_FAILED');
        this.signature = signature;
    }
}

class SignedResponse {
    /**
     * Represents a cryptographically signed tool response.
     */
    constructor(data) {
        this.tool_id = data.tool_id;
        this.data = data.data;
        this.signature = data.signature;
        this.signature_id = data.signature_id || '';
        this.timestamp = data.timestamp || Date.now() / 1000;
        this.nonce = data.nonce || null;
        this.is_verified = data.is_verified || false;
    }

    /**
     * Convert to dictionary for serialization.
     */
    toDict() {
        return {
            tool_id: this.tool_id,
            data: this.data,
            signature: this.signature,
            signature_id: this.signature_id,
            timestamp: this.timestamp,
            nonce: this.nonce,
            is_verified: this.is_verified
        };
    }

    /**
     * Get signature preview (first 16 characters + ...).
     */
    getSignaturePreview() {
        if (!this.signature) return 'No signature';
        return this.signature.substring(0, 16) + '...';
    }

    /**
     * Get human-readable timestamp.
     */
    getFormattedTimestamp() {
        return new Date(this.timestamp * 1000).toISOString();
    }
}

class TrustChainClient {
    /**
     * JavaScript client for TrustChain API.
     * 
     * @param {string} baseUrl - Base URL of TrustChain server
     * @param {Object} options - Configuration options
     */
    constructor(baseUrl = 'http://localhost:8000', options = {}) {
        this.baseUrl = baseUrl.replace(/\/$/, ''); // Remove trailing slash
        this.options = {
            timeout: 30000,
            retries: 3,
            autoVerify: true,
            ...options
        };

        // WebSocket connection for real-time updates
        this.websocket = null;
        this.wsCallbacks = new Map();

        // Statistics
        this.stats = {
            totalCalls: 0,
            successfulCalls: 0,
            failedCalls: 0,
            verificationSuccess: 0,
            verificationFailed: 0
        };
    }

    /**
     * Call a registered tool on the TrustChain server.
     * 
     * @param {string} toolName - Name of the tool to call
     * @param {Object} parameters - Parameters to pass to the tool
     * @param {string|null} nonce - Optional nonce for replay protection
     * @returns {Promise<SignedResponse>} Signed response from the tool
     */
    async callTool(toolName, parameters = {}, nonce = null) {
        const startTime = Date.now();
        this.stats.totalCalls++;

        try {
            const response = await this._makeRequest('/api/tools/call', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    tool_name: toolName,
                    parameters: parameters,
                    nonce: nonce
                })
            });

            if (!response.success) {
                this.stats.failedCalls++;
                throw new TrustChainError(
                    response.error || 'Tool execution failed',
                    'TOOL_EXECUTION_FAILED',
                    { toolName, parameters }
                );
            }

            const signedResponse = new SignedResponse(response.signed_response);
            this.stats.successfulCalls++;

            // Auto-verify if enabled
            if (this.options.autoVerify) {
                const isValid = await this.verify(signedResponse);
                if (!isValid) {
                    this.stats.verificationFailed++;
                    throw new VerificationError(
                        `Tool response signature verification failed for ${toolName}`,
                        signedResponse.signature
                    );
                }
                this.stats.verificationSuccess++;
            }

            return signedResponse;

        } catch (error) {
            this.stats.failedCalls++;
            if (error instanceof TrustChainError) {
                throw error;
            }
            throw new TrustChainError(
                `Failed to call tool ${toolName}: ${error.message}`,
                'NETWORK_ERROR',
                { toolName, parameters, originalError: error.message }
            );
        }
    }

    /**
     * Verify a signed response.
     * 
     * @param {SignedResponse} signedResponse - Response to verify
     * @returns {Promise<boolean>} True if signature is valid
     */
    async verify(signedResponse) {
        try {
            const response = await this._makeRequest('/api/tools/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    signed_response: signedResponse.toDict()
                })
            });

            return response.valid;

        } catch (error) {
            console.warn('Verification request failed:', error.message);
            return false;
        }
    }

    /**
     * Get list of available tools.
     * 
     * @returns {Promise<Array>} List of available tools
     */
    async getTools() {
        try {
            const response = await this._makeRequest('/api/tools');
            return response.tools;
        } catch (error) {
            throw new TrustChainError(
                `Failed to get tools list: ${error.message}`,
                'API_ERROR'
            );
        }
    }

    /**
     * Get TrustChain server statistics.
     * 
     * @returns {Promise<Object>} Server statistics
     */
    async getServerStats() {
        try {
            const response = await this._makeRequest('/api/stats');
            return response;
        } catch (error) {
            throw new TrustChainError(
                `Failed to get server stats: ${error.message}`,
                'API_ERROR'
            );
        }
    }

    /**
     * Get client-side statistics.
     * 
     * @returns {Object} Client statistics
     */
    getClientStats() {
        return {
            ...this.stats,
            successRate: this.stats.totalCalls > 0
                ? (this.stats.successfulCalls / this.stats.totalCalls * 100).toFixed(2) + '%'
                : 'N/A',
            verificationRate: this.stats.verificationSuccess + this.stats.verificationFailed > 0
                ? (this.stats.verificationSuccess / (this.stats.verificationSuccess + this.stats.verificationFailed) * 100).toFixed(2) + '%'
                : 'N/A'
        };
    }

    /**
     * Check server health.
     * 
     * @returns {Promise<Object>} Health status
     */
    async healthCheck() {
        try {
            const response = await this._makeRequest('/health');
            return response;
        } catch (error) {
            throw new TrustChainError(
                `Health check failed: ${error.message}`,
                'HEALTH_CHECK_FAILED'
            );
        }
    }

    /**
     * Connect to WebSocket for real-time updates.
     * 
     * @param {Function} onMessage - Callback for WebSocket messages
     * @returns {Promise<void>}
     */
    async connectWebSocket(onMessage = null) {
        if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
            console.warn('WebSocket already connected');
            return;
        }

        const wsUrl = this.baseUrl.replace(/^http/, 'ws') + '/ws';

        return new Promise((resolve, reject) => {
            try {
                this.websocket = new WebSocket(wsUrl);

                this.websocket.onopen = () => {
                    console.log('Connected to TrustChain WebSocket');
                    resolve();
                };

                this.websocket.onmessage = (event) => {
                    try {
                        const message = JSON.parse(event.data);

                        // Call registered callbacks
                        this.wsCallbacks.forEach(callback => {
                            try {
                                callback(message);
                            } catch (error) {
                                console.error('WebSocket callback error:', error);
                            }
                        });

                        // Call provided callback
                        if (onMessage) {
                            onMessage(message);
                        }
                    } catch (error) {
                        console.error('Failed to parse WebSocket message:', error);
                    }
                };

                this.websocket.onerror = (error) => {
                    console.error('WebSocket error:', error);
                    reject(new TrustChainError('WebSocket connection failed', 'WEBSOCKET_ERROR'));
                };

                this.websocket.onclose = () => {
                    console.log('WebSocket connection closed');
                    this.websocket = null;
                };

            } catch (error) {
                reject(new TrustChainError(`Failed to create WebSocket: ${error.message}`, 'WEBSOCKET_ERROR'));
            }
        });
    }

    /**
     * Disconnect WebSocket.
     */
    disconnectWebSocket() {
        if (this.websocket) {
            this.websocket.close();
            this.websocket = null;
        }
    }

    /**
     * Register callback for WebSocket messages.
     * 
     * @param {string} id - Callback ID
     * @param {Function} callback - Callback function
     */
    onWebSocketMessage(id, callback) {
        this.wsCallbacks.set(id, callback);
    }

    /**
     * Unregister WebSocket callback.
     * 
     * @param {string} id - Callback ID
     */
    offWebSocketMessage(id) {
        this.wsCallbacks.delete(id);
    }

    /**
     * Make HTTP request with error handling and retries.
     * 
     * @private
     */
    async _makeRequest(endpoint, options = {}) {
        const url = this.baseUrl + endpoint;
        let lastError;

        for (let attempt = 1; attempt <= this.options.retries; attempt++) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), this.options.timeout);

                const response = await fetch(url, {
                    ...options,
                    signal: controller.signal
                });

                clearTimeout(timeoutId);

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                return await response.json();

            } catch (error) {
                lastError = error;

                if (attempt < this.options.retries) {
                    // Exponential backoff
                    const delay = Math.min(1000 * Math.pow(2, attempt - 1), 5000);
                    await new Promise(resolve => setTimeout(resolve, delay));
                    continue;
                }

                break;
            }
        }

        throw lastError;
    }
}

/**
 * TrustChainVerifier - Standalone signature verification without server.
 * 
 * Uses Web Crypto API (browser) or Node.js crypto for Ed25519 verification.
 * 
 * @example
 * const verifier = new TrustChainVerifier({ publicKey: 'base64_ed25519_key' });
 * const isValid = await verifier.verify(signedResponse);
 */
class TrustChainVerifier {
    /**
     * Create a standalone verifier.
     * 
     * @param {Object} options - Configuration
     * @param {string} options.publicKey - Base64-encoded Ed25519 public key
     * @param {string} options.publicKeyUrl - URL to fetch public key from
     */
    constructor(options = {}) {
        this.publicKey = options.publicKey || null;
        this.publicKeyUrl = options.publicKeyUrl || null;
        this._cryptoKey = null;
        this._isNodeJS = typeof window === 'undefined';
    }

    /**
     * Initialize the verifier by loading the public key.
     */
    async initialize() {
        if (!this.publicKey && this.publicKeyUrl) {
            await this._fetchPublicKey();
        }

        if (this.publicKey) {
            await this._importPublicKey();
        }

        return this;
    }

    /**
     * Verify a signed response.
     * 
     * @param {SignedResponse|Object} signedResponse - Response to verify
     * @returns {Promise<boolean>} True if signature is valid
     */
    async verify(signedResponse) {
        if (!this._cryptoKey && !this.publicKey) {
            throw new TrustChainError('Verifier not initialized. Call initialize() first or provide publicKey.');
        }

        if (!this._cryptoKey) {
            await this._importPublicKey();
        }

        try {
            // Recreate canonical data as Python does
            const canonicalData = {
                tool_id: signedResponse.tool_id,
                data: signedResponse.data,
                timestamp: signedResponse.timestamp,
                nonce: signedResponse.nonce,
                parent_signature: signedResponse.parent_signature || null
            };

            // Serialize with sorted keys (matching Python's sort_keys=True)
            const jsonData = this._canonicalStringify(canonicalData);
            const dataBytes = new TextEncoder().encode(jsonData);

            // Decode signature from base64
            const signatureBytes = this._base64ToArrayBuffer(signedResponse.signature);

            // Verify signature
            if (this._isNodeJS) {
                return this._verifyNodeJS(dataBytes, signatureBytes);
            } else {
                return await this._verifyBrowser(dataBytes, signatureBytes);
            }
        } catch (error) {
            console.warn('Verification failed:', error.message);
            return false;
        }
    }

    /**
     * Verify a chain of linked responses.
     * 
     * @param {Array<SignedResponse>} chain - Array of signed responses
     * @returns {Promise<boolean>} True if all signatures valid and chain is unbroken
     */
    async verifyChain(chain) {
        if (!chain || chain.length === 0) {
            return true;
        }

        // Verify first response
        if (!await this.verify(chain[0])) {
            return false;
        }

        // Verify chain links
        for (let i = 1; i < chain.length; i++) {
            const current = chain[i];
            const previous = chain[i - 1];

            // Check chain link
            if (current.parent_signature !== previous.signature) {
                return false;
            }

            // Verify signature
            if (!await this.verify(current)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Fetch public key from URL.
     * @private
     */
    async _fetchPublicKey() {
        try {
            const response = await fetch(this.publicKeyUrl);
            const data = await response.json();
            this.publicKey = data.public_key || data.publicKey;
        } catch (error) {
            throw new TrustChainError(`Failed to fetch public key: ${error.message}`);
        }
    }

    /**
     * Import public key for crypto operations.
     * @private
     */
    async _importPublicKey() {
        const keyBytes = this._base64ToArrayBuffer(this.publicKey);

        if (this._isNodeJS) {
            // Node.js: Use crypto module
            const crypto = require('crypto');
            this._cryptoKey = crypto.createPublicKey({
                key: Buffer.concat([
                    // Ed25519 public key prefix for PKCS#8
                    Buffer.from('302a300506032b6570032100', 'hex'),
                    Buffer.from(keyBytes)
                ]),
                format: 'der',
                type: 'spki'
            });
        } else {
            // Browser: Use Web Crypto API
            // Note: Ed25519 support in Web Crypto is limited, use SubtleCrypto if available
            try {
                this._cryptoKey = await crypto.subtle.importKey(
                    'raw',
                    keyBytes,
                    { name: 'Ed25519' },
                    false,
                    ['verify']
                );
            } catch (error) {
                // Fallback: Ed25519 not supported, store raw key for later
                console.warn('Ed25519 not natively supported, using fallback');
                this._cryptoKey = { raw: keyBytes, fallback: true };
            }
        }
    }

    /**
     * Verify signature in Node.js.
     * @private
     */
    _verifyNodeJS(dataBytes, signatureBytes) {
        const crypto = require('crypto');
        return crypto.verify(
            null, // Ed25519 doesn't use digest algorithm
            Buffer.from(dataBytes),
            this._cryptoKey,
            Buffer.from(signatureBytes)
        );
    }

    /**
     * Verify signature in browser using Web Crypto.
     * @private
     */
    async _verifyBrowser(dataBytes, signatureBytes) {
        if (this._cryptoKey.fallback) {
            // Ed25519 not supported natively - would need external library
            console.warn('Ed25519 verification requires native support or external library');
            return false;
        }

        return await crypto.subtle.verify(
            { name: 'Ed25519' },
            this._cryptoKey,
            signatureBytes,
            dataBytes
        );
    }

    /**
     * Convert base64 string to ArrayBuffer.
     * @private
     */
    _base64ToArrayBuffer(base64) {
        if (this._isNodeJS) {
            return Buffer.from(base64, 'base64');
        } else {
            const binaryString = atob(base64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        }
    }

    /**
     * Canonical JSON stringify with sorted keys (matches Python).
     * @private
     */
    _canonicalStringify(obj) {
        return JSON.stringify(obj, Object.keys(obj).sort(), 0)
            .replace(/,/g, ',')
            .replace(/:/g, ':');
    }
}

// Utility functions
const TrustChainUtils = {
    /**
     * Generate a random nonce.
     */
    generateNonce() {
        return 'nonce_' + Math.random().toString(36).substring(2) + '_' + Date.now();
    },

    /**
     * Format execution time.
     */
    formatExecutionTime(ms) {
        if (ms < 1000) {
            return `${ms.toFixed(1)}ms`;
        } else {
            return `${(ms / 1000).toFixed(2)}s`;
        }
    },

    /**
     * Validate tool name.
     */
    validateToolName(name) {
        if (!name || typeof name !== 'string') {
            throw new TrustChainError('Tool name must be a non-empty string');
        }
        if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(name)) {
            throw new TrustChainError('Tool name must start with a letter and contain only letters, numbers, and underscores');
        }
        return true;
    }
};

// Export for different environments
if (typeof module !== 'undefined' && module.exports) {
    // Node.js
    module.exports = {
        TrustChainClient,
        TrustChainVerifier,
        SignedResponse,
        TrustChainError,
        VerificationError,
        TrustChainUtils
    };
} else if (typeof window !== 'undefined') {
    // Browser
    window.TrustChain = {
        TrustChainClient,
        TrustChainVerifier,
        SignedResponse,
        TrustChainError,
        VerificationError,
        TrustChainUtils
    };
} 