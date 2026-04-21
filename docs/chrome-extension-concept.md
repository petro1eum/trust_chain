# TrustChain Chrome Extension — "TrustChain Verifier"

**Status**: Concept Design  
**Target**: Chrome Web Store / Firefox Add-ons  
**Version**: v0.1 (concept)

## Vision

The browser padlock (🔒) tells users "this connection is encrypted."  
The TrustChain extension (🛡️) tells users "this AI content is verified."

## Functionality

### V1: Badge-Aware Detection

The extension detects pages that embed `badge.js` and surfaces verification 
status in the browser toolbar.

**How it works**:

1. Content script detects `<script>` tags with `data-agent` attribute
2. Extracts agent ID(s) from the page
3. Fetches agent status from `keys.trust-chain.ai/api/pub/agents/{id}`
4. Shows extension icon state:
   - 🟢 Green shield: All agents on this page are verified
   - 🟡 Amber: Some agents pending/unknown
   - ⬜ Gray: No TrustChain agents detected
5. Popup shows agent details (name, fingerprint, cert expiry)

### V2: Signature Detection

The extension scans page content for TrustChain signature patterns and 
verifies them in real-time.

**Detection targets**:
- `__trustchain_signature__` in JSON blocks or data attributes
- `data-tc-signature` attributes on HTML elements
- `X-TrustChain-Signature` response headers

**Verification flow**:
1. Extract signature + data from page element
2. Fetch agent's X.509 certificate
3. Verify Ed25519 signature locally (using Web Crypto API)
4. Inject 🛡️ badge next to verified elements
5. Inject ⚠️ "Unverified" indicator next to AI-generated content without signatures

### V3: AI Content Heuristic

Advanced detection of AI-generated content that **lacks** TrustChain signatures:

- Known AI chat interfaces (ChatGPT, Claude, Gemini)
- Embedded AI widgets (chatbots, copilots)
- Content marked with `ai-generated` metadata

Shows: ⚠️ "AI content detected — not cryptographically verified"

## Architecture

```
┌─────────────────────────────────────┐
│           Browser Extension          │
├──────────┬──────────┬───────────────┤
│ Popup UI │ Options  │ Background SW │
│ (status) │ (config) │ (cert cache)  │
├──────────┴──────────┴───────────────┤
│          Content Script              │
│  ┌──────────┐  ┌──────────────────┐ │
│  │ Detector │  │ Badge Injector   │ │
│  │ (scan    │  │ (injects shields │ │
│  │  page)   │  │  into DOM)       │ │
│  └──────────┘  └──────────────────┘ │
├─────────────────────────────────────┤
│     Web Crypto API (Ed25519)         │
│     ↕ Local signature verification   │
├─────────────────────────────────────┤
│     keys.trust-chain.ai/api/pub      │
│     ↕ Certificate fetch + cache      │
└─────────────────────────────────────┘
```

## File Structure

```
trustchain-verifier/
├── manifest.json          # MV3 manifest
├── background.js          # Service worker (cert cache, API calls)
├── content.js             # Content script (page scanning, badge injection)
├── popup/
│   ├── popup.html         # Extension popup
│   └── popup.js           # Popup logic
├── options/
│   ├── options.html       # Settings page
│   └── options.js         # Settings logic
├── icons/
│   ├── icon-16.png
│   ├── icon-48.png
│   └── icon-128.png
└── lib/
    └── verify.js          # Ed25519 verification via Web Crypto
```

## Manifest (MV3)

```json
{
  "manifest_version": 3,
  "name": "TrustChain Verifier",
  "description": "Cryptographic verification for AI agent content",
  "version": "0.1.0",
  "permissions": ["activeTab"],
  "host_permissions": ["https://keys.trust-chain.ai/*"],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["content.js"],
    "run_at": "document_idle"
  }],
  "action": {
    "default_popup": "popup/popup.html",
    "default_icon": {
      "16": "icons/icon-16.png",
      "48": "icons/icon-48.png",
      "128": "icons/icon-128.png"
    }
  }
}
```

## Privacy

- Extension ONLY contacts `keys.trust-chain.ai` (certificate registry)
- No user data is collected or transmitted
- No browsing history is stored
- All signature verification happens locally via Web Crypto API
- Certificate cache is stored in `chrome.storage.local` (per-user, never shared)

## Implementation Timeline

| Phase | Scope | Estimate |
|-------|-------|----------|
| V1 | Badge detection + popup | 3-5 days |
| V2 | Signature verification + badge injection | 1-2 weeks |
| V3 | AI content heuristic | Research phase |
