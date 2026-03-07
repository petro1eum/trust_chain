# TrustChain JavaScript SDK

> Cryptographically verified tool execution for JavaScript and Node.js applications

[![npm version](https://badge.fury.io/js/trustchain-js.svg)](https://badge.fury.io/js/trustchain-js)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 Quick Start

### Installation

#### NPM
```bash
npm install trustchain-js
```

#### CDN (Browser)
```html
<script src="https://unpkg.com/trustchain-js@2.0.0/trustchain.js"></script>
```

### Basic Usage

#### Node.js
```javascript
const { TrustChainClient } = require('trustchain-js');

const client = new TrustChainClient('http://localhost:8000');

// Call a verified tool
const response = await client.callTool('weather_api', {
    city: 'London'
});

console.log('Weather data:', response.data);
console.log('Signature verified:', response.is_verified);
```

#### Browser
```html
<!DOCTYPE html>
<html>
<head>
    <script src="https://unpkg.com/trustchain-js@2.0.0/trustchain.js"></script>
</head>
<body>
    <script>
        const client = new TrustChain.TrustChainClient('http://localhost:8000');
        
        async function callWeatherTool() {
            try {
                const response = await client.callTool('weather_api', {
                    city: 'London'
                });
                
                document.getElementById('result').innerHTML = `
                    <h3>Weather for London</h3>
                    <p>Temperature: ${response.data.temperature}°C</p>
                    <p>Verified: ${response.is_verified ? '✅' : '❌'}</p>
                    <p>Signature: ${response.getSignaturePreview()}</p>
                `;
            } catch (error) {
                console.error('Tool call failed:', error);
            }
        }
    </script>
</body>
</html>
```

## 📖 Features

- 🔐 **Cryptographic Verification** - Every tool response is cryptographically signed
- 🌐 **Cross-Platform** - Works in Node.js and browsers
- ⚡ **Real-time Updates** - WebSocket support for live notifications
- 🔄 **Automatic Retries** - Built-in retry logic with exponential backoff
- 📊 **Statistics** - Track tool usage and verification rates
- 🛡️ **Error Handling** - Comprehensive error handling and validation

## 🔧 API Reference

### TrustChainClient

#### Constructor
```javascript
const client = new TrustChainClient(baseUrl, options);
```

**Parameters:**
- `baseUrl` (string): TrustChain server URL (default: 'http://localhost:8000')
- `options` (object):
  - `timeout` (number): Request timeout in ms (default: 30000)
  - `retries` (number): Number of retries (default: 3)
  - `autoVerify` (boolean): Auto-verify responses (default: true)

#### Methods

##### callTool(toolName, parameters, nonce)
Call a registered tool with cryptographic verification.

```javascript
const response = await client.callTool('calculator', {
    operation: 'add',
    a: 5,
    b: 3
});
```

##### verify(signedResponse)
Manually verify a signed response.

```javascript
const isValid = await client.verify(response);
```

##### getTools()
Get list of available tools.

```javascript
const tools = await client.getTools();
console.log('Available tools:', tools);
```

##### getServerStats()
Get server statistics.

```javascript
const stats = await client.getServerStats();
console.log('Server uptime:', stats.uptime_seconds);
```

##### healthCheck()
Check server health.

```javascript
const health = await client.healthCheck();
console.log('Server status:', health.status);
```

#### WebSocket Support

Connect to real-time updates:

```javascript
// Connect to WebSocket
await client.connectWebSocket((message) => {
    console.log('WebSocket message:', message);
});

// Register specific callback
client.onWebSocketMessage('tool-calls', (message) => {
    if (message.type === 'tool_call') {
        console.log(`Tool ${message.tool_name} executed in ${message.execution_time_ms}ms`);
    }
});

// Disconnect
client.disconnectWebSocket();
```

### SignedResponse

Represents a cryptographically signed tool response.

```javascript
const response = new SignedResponse({
    tool_id: 'weather_api',
    data: { temperature: 22, city: 'London' },
    signature: 'base64-encoded-signature...',
    timestamp: Date.now() / 1000
});

console.log('Tool ID:', response.tool_id);
console.log('Data:', response.data);
console.log('Is verified:', response.is_verified);
console.log('Signature preview:', response.getSignaturePreview());
console.log('Timestamp:', response.getFormattedTimestamp());
```

### Utilities

```javascript
const { TrustChainUtils } = require('trustchain-js');

// Generate nonce
const nonce = TrustChainUtils.generateNonce();

// Format execution time
const formatted = TrustChainUtils.formatExecutionTime(1234.5); // "1.23s"

// Validate tool name
TrustChainUtils.validateToolName('my_tool'); // true
```

## 📋 Examples

### 1. Weather Service Integration

```javascript
const { TrustChainClient } = require('trustchain-js');

class WeatherService {
    constructor() {
        this.client = new TrustChainClient('http://localhost:8000');
    }
    
    async getWeather(city) {
        try {
            const response = await this.client.callTool('weather_api', { city });
            
            if (!response.is_verified) {
                throw new Error('Weather data could not be verified');
            }
            
            return {
                city: response.data.city,
                temperature: response.data.temperature,
                condition: response.data.condition,
                verified: true,
                timestamp: response.timestamp
            };
        } catch (error) {
            console.error('Weather service error:', error);
            throw error;
        }
    }
}

// Usage
const weather = new WeatherService();
const data = await weather.getWeather('Paris');
console.log(`Weather in ${data.city}: ${data.temperature}°C`);
```

### 2. Financial Calculator with Verification

```javascript
const { TrustChainClient, VerificationError } = require('trustchain-js');

class FinancialCalculator {
    constructor() {
        this.client = new TrustChainClient('http://localhost:8000', {
            autoVerify: true // Always verify financial calculations
        });
    }
    
    async calculateCompoundInterest(principal, rate, time) {
        try {
            const response = await this.client.callTool('financial_calculator', {
                operation: 'compound_interest',
                principal,
                rate,
                time
            });
            
            return {
                principal,
                rate,
                time,
                final_amount: response.data.final_amount,
                interest_earned: response.data.interest_earned,
                verified: response.is_verified,
                signature: response.signature
            };
            
        } catch (error) {
            if (error instanceof VerificationError) {
                console.error('CRITICAL: Financial calculation could not be verified!');
                throw new Error('Cannot proceed with unverified financial data');
            }
            throw error;
        }
    }
}
```

### 3. Real-time Dashboard

```html
<!DOCTYPE html>
<html>
<head>
    <title>TrustChain Dashboard</title>
    <script src="https://unpkg.com/trustchain-js@2.0.0/trustchain.js"></script>
</head>
<body>
    <div id="dashboard">
        <h1>TrustChain Real-time Dashboard</h1>
        <div id="stats"></div>
        <div id="tools"></div>
        <div id="activity"></div>
    </div>

    <script>
        class Dashboard {
            constructor() {
                this.client = new TrustChain.TrustChainClient();
                this.init();
            }
            
            async init() {
                // Connect WebSocket for real-time updates
                await this.client.connectWebSocket((message) => {
                    this.handleRealtimeUpdate(message);
                });
                
                // Load initial data
                await this.loadStats();
                await this.loadTools();
            }
            
            async loadStats() {
                const serverStats = await this.client.getServerStats();
                const clientStats = this.client.getClientStats();
                
                document.getElementById('stats').innerHTML = `
                    <h2>Statistics</h2>
                    <p>Server Tools: ${serverStats.total_tools}</p>
                    <p>Total Calls: ${serverStats.total_calls}</p>
                    <p>Cache Size: ${serverStats.cache_size}</p>
                    <p>Client Success Rate: ${clientStats.successRate}</p>
                `;
            }
            
            async loadTools() {
                const tools = await this.client.getTools();
                
                const toolsHtml = tools.map(tool => `
                    <div class="tool">
                        <h3>${tool.name}</h3>
                        <p>${tool.description}</p>
                        <button onclick="dashboard.callTool('${tool.name}')">
                            Test Tool
                        </button>
                    </div>
                `).join('');
                
                document.getElementById('tools').innerHTML = `
                    <h2>Available Tools</h2>
                    ${toolsHtml}
                `;
            }
            
            async callTool(toolName) {
                try {
                    const response = await this.client.callTool(toolName, {
                        test: true
                    });
                    
                    this.addActivity(`✅ ${toolName} executed successfully`);
                } catch (error) {
                    this.addActivity(`❌ ${toolName} failed: ${error.message}`);
                }
            }
            
            handleRealtimeUpdate(message) {
                if (message.type === 'tool_call') {
                    this.addActivity(
                        `🔧 ${message.tool_name} called (${message.execution_time_ms}ms)`
                    );
                }
            }
            
            addActivity(text) {
                const activityDiv = document.getElementById('activity');
                const timestamp = new Date().toLocaleTimeString();
                activityDiv.innerHTML = `
                    <div>[${timestamp}] ${text}</div>
                    ${activityDiv.innerHTML}
                `;
            }
        }
        
        const dashboard = new Dashboard();
    </script>
</body>
</html>
```

## 🔧 Setting up TrustChain Server

Before using the JavaScript SDK, you need a running TrustChain server:

### Python Server Setup

```bash
# Install TrustChain with web support
pip install 'trustchain[web]'

# Create server script
cat > server.py << EOF
from trustchain.v2 import TrustChain, TrustChainConfig
from trustchain.web_api import start_server

# Create TrustChain instance
tc = TrustChain(TrustChainConfig())

# Register some tools
@tc.tool('weather_api')
def get_weather(city):
    return {
        'city': city,
        'temperature': 22,
        'condition': 'Sunny'
    }

@tc.tool('calculator')
def calculate(operation, a, b):
    if operation == 'add':
        return {'result': a + b}
    elif operation == 'multiply':
        return {'result': a * b}
    else:
        raise ValueError(f'Unknown operation: {operation}')

# Start server
if __name__ == '__main__':
    start_server(tc, host='0.0.0.0', port=8000)
EOF

# Run server
python server.py
```

### Test Connection

```javascript
const { TrustChainClient } = require('trustchain-js');

async function test() {
    const client = new TrustChainClient('http://localhost:8000');
    
    // Health check
    const health = await client.healthCheck();
    console.log('Server status:', health.status);
    
    // List tools
    const tools = await client.getTools();
    console.log('Available tools:', tools.map(t => t.name));
    
    // Call tool
    const weather = await client.callTool('weather_api', { city: 'London' });
    console.log('Weather:', weather.data);
    console.log('Verified:', weather.is_verified);
}

test().catch(console.error);
```

## 🚨 Error Handling

```javascript
const { TrustChainClient, TrustChainError, VerificationError } = require('trustchain-js');

async function robustToolCall() {
    const client = new TrustChainClient();
    
    try {
        const response = await client.callTool('risky_tool', { data: 'test' });
        return response;
        
    } catch (error) {
        if (error instanceof VerificationError) {
            console.error('SECURITY ALERT: Signature verification failed!');
            // Handle unverified response
            
        } else if (error instanceof TrustChainError) {
            switch (error.code) {
                case 'TOOL_EXECUTION_FAILED':
                    console.error('Tool execution error:', error.message);
                    break;
                case 'NETWORK_ERROR':
                    console.error('Network error:', error.message);
                    // Implement retry logic
                    break;
                default:
                    console.error('TrustChain error:', error.message);
            }
        } else {
            console.error('Unexpected error:', error);
        }
        
        throw error;
    }
}
```

## 📊 Performance & Configuration

### Optimizing for Production

```javascript
const client = new TrustChainClient('https://api.example.com', {
    timeout: 10000,        // 10 second timeout
    retries: 5,            // More retries for production
    autoVerify: true       // Always verify in production
});

// Monitor performance
setInterval(async () => {
    const stats = client.getClientStats();
    console.log('Success rate:', stats.successRate);
    console.log('Verification rate:', stats.verificationRate);
}, 60000); // Every minute
```

### Batch Operations

```javascript
async function batchWeatherCheck(cities) {
    const promises = cities.map(city => 
        client.callTool('weather_api', { city })
    );
    
    const responses = await Promise.allSettled(promises);
    
    return responses.map((result, index) => ({
        city: cities[index],
        success: result.status === 'fulfilled',
        data: result.status === 'fulfilled' ? result.value.data : null,
        error: result.status === 'rejected' ? result.reason.message : null
    }));
}
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📖 [Documentation](https://github.com/petro1eum/trust_chain/wiki)
- 🐛 [Issue Tracker](https://github.com/petro1eum/trust_chain/issues)
- 💬 [Discussions](https://github.com/petro1eum/trust_chain/discussions)

---

Made with ❤️ by the TrustChain Team 