# TrustChain -- 用户指南

## 什么是 TrustChain？

TrustChain 是一个用于 AI 工具响应加密签名的 Python 库。它解决了信任问题：当 AI 代理调用函数（工具）时，无法保证结果是真实的而非幻觉。

TrustChain 为每个响应添加：
- 加密签名（Ed25519）
- 唯一的随机数（重放攻击保护）
- 时间戳
- 可选：与上一步的链接（信任链）

---

## 系统要求

- **Python 3.10+**（推荐 3.13）
- 包管理器：`uv`（推荐）或 `pip`

---

## 安装

推荐使用 **uv** 进行快速安装：

```bash
uv pip install trustchain
```

或标准 pip：

```bash
pip install trustchain
```

附加功能：

```bash
uv pip install trustchain[integrations]  # LangChain + MCP
uv pip install trustchain[ai]            # OpenAI + Anthropic + LangChain
uv pip install trustchain[mcp]           # 仅 MCP 服务器
uv pip install trustchain[redis]         # 分布式随机数存储
uv pip install trustchain[all]           # 全部功能
```

---

## 快速开始

### 基本用法

```python
from trustchain import TrustChain

# 创建 TrustChain 实例
tc = TrustChain()

# 将函数注册为签名工具
@tc.tool("weather")
def get_weather(city: str) -> dict:
    """获取城市天气。"""
    return {"city": city, "temp": 22, "conditions": "sunny"}

# 调用函数 -- 获取签名响应
result = get_weather("Beijing")

# result 是 SignedResponse 对象
print(result.data)       # {'city': 'Beijing', 'temp': 22, ...}
print(result.signature)  # Base64 编码的 Ed25519 签名
print(result.nonce)      # 用于重放保护的 UUID
```

### 签名验证

```python
# 验证响应真实性
is_valid = tc.verify(result)
print(is_valid)  # True

# 重复验证相同的随机数 -- 错误
try:
    tc.verify(result)
except NonceReplayError:
    print("检测到重放攻击！")
```

---

## 核心概念

### SignedResponse

当您调用使用 `@tc.tool()` 装饰器包装的函数时，它返回的不是原始数据，而是 `SignedResponse` 对象：

| 字段 | 描述 |
|------|------|
| `data` | 函数结果（任意类型） |
| `signature` | Base64 格式的 Ed25519 签名 |
| `signature_id` | 唯一签名 ID（UUID） |
| `timestamp` | 创建时的 Unix 时间戳 |
| `nonce` | 用于重放保护的唯一 ID |
| `tool_id` | 工具标识符 |
| `parent_signature` | 与上一步的链接（信任链） |

### 签名工作原理

1. 创建数据的规范表示（JSON）
2. 使用 SHA-256 对数据进行哈希
3. 使用 Ed25519 私钥对哈希进行签名
4. 将签名编码为 Base64

验证过程：
1. 恢复规范表示
2. 从 Base64 解码签名
3. 公钥验证签名

### 重放攻击保护

Nonce（一次性数字）确保每个响应只能验证一次。

攻击场景：
```
1. 黑客拦截响应"转账 $100"
2. 黑客发送 100 次
3. 被盗 $10,000
```

使用 TrustChain：
```python
tc.verify(result)  # OK -- 第一次
tc.verify(result)  # NonceReplayError -- 随机数已使用
```

---

## 信任链（Chain of Trust）

允许加密链接多个操作。

### 为什么需要这个？

当 AI 执行多步任务时：
1. 数据搜索
2. 分析
3. 报告生成

您需要证明第 2 步是基于第 1 步执行的，而不是捏造的。

### 使用方法

```python
from trustchain import TrustChain

tc = TrustChain()

# 步骤 1：搜索（无父级）
step1 = tc._signer.sign("search", {"query": "balance", "results": [100, 200]})

# 步骤 2：分析（引用步骤 1）
step2 = tc._signer.sign(
    "analyze", 
    {"summary": "total=300"},
    parent_signature=step1.signature  # 与上一步的链接
)

# 步骤 3：报告（引用步骤 2）
step3 = tc._signer.sign(
    "report",
    {"text": "Balance is 300"},
    parent_signature=step2.signature
)

# 验证整个链
chain = [step1, step2, step3]
is_valid = tc.verify_chain(chain)
print(is_valid)  # True -- 链完整
```

### verify_chain 检查什么？

1. 每个签名有效
2. 每个 `parent_signature` 与上一步的 `signature` 匹配
3. 链未断开

---

## 配置

### 基本选项

```python
from trustchain import TrustChain, TrustChainConfig

config = TrustChainConfig(
    algorithm="ed25519",      # 签名算法
    enable_nonce=True,        # 重放攻击保护
    enable_cache=True,        # 响应缓存
    cache_ttl=3600,           # 缓存生命周期（秒）
    nonce_ttl=86400,          # 随机数生命周期（秒）
    key_file="keys.json",     # 密钥存储文件
)

tc = TrustChain(config)
```

### 密钥轮换

```python
# 生成新密钥
old_key = tc.get_key_id()
new_key = tc.rotate_keys()  # 如果配置了 key_file，自动保存

print(f"轮换：{old_key[:16]} -> {new_key[:16]}")

# 导出公钥用于外部验证
public_key = tc.export_public_key()
```

> 轮换后，所有先前的签名都将失效！

### 分布式配置（Redis）

用于多服务器：

```python
config = TrustChainConfig(
    nonce_backend="redis",
    redis_url="redis://localhost:6379/0",
    nonce_ttl=86400,
)

tc = TrustChain(config)
```

### 多租户（Multi-Tenancy）

用于有不同客户的 SaaS：

```python
from trustchain import TenantManager

manager = TenantManager(
    redis_url="redis://localhost:6379",
    key_storage_dir="./keys"  # 客户密钥存储位置
)

# 获取特定客户的 TrustChain
tc_acme = manager.get_or_create("acme_corp")
tc_beta = manager.get_or_create("beta_inc")

# 每个客户都有自己的密钥
print(tc_acme.get_key_id())  # key-abc123...
print(tc_beta.get_key_id())  # key-xyz789...
```

---

## 集成

### OpenAI / Anthropic Schema

TrustChain 自动为函数生成 JSON Schema：

```python
# OpenAI 格式
schema = tc.get_tool_schema("weather")
# {
#   "type": "function",
#   "function": {
#     "name": "weather",
#     "description": "获取城市天气。",
#     "parameters": {...}
#   }
# }

# Anthropic 格式
schema = tc.get_tool_schema("weather", format="anthropic")
# {"name": "weather", "input_schema": {...}}

# 一次获取所有工具
all_schemas = tc.get_tools_schema()
```

### Pydantic V2

完全支持 Pydantic 模型：

```python
from pydantic import BaseModel, Field

class SearchParams(BaseModel):
    query: str = Field(..., description="搜索查询字符串")
    limit: int = Field(10, le=100, description="最大结果数")

@tc.tool("search")
def search(params: SearchParams) -> list:
    """搜索文档。"""
    return []

# Schema 自动包含描述和约束
schema = tc.get_tool_schema("search")
# properties.query.description == "搜索查询字符串"
# properties.limit.maximum == 100
```

### LangChain

```python
from trustchain.integrations.langchain import to_langchain_tools

# 将所有 TrustChain 工具转换为 LangChain 格式
lc_tools = to_langchain_tools(tc)

# 与代理一起使用
from langchain.agents import AgentExecutor
executor = AgentExecutor(agent=agent, tools=lc_tools)
```

### MCP 服务器（Claude Desktop）

```python
from trustchain.integrations.mcp import serve_mcp

@tc.tool("calculator")
def add(a: int, b: int) -> int:
    return a + b

# 启动 MCP 服务器
serve_mcp(tc)
```

在 Claude Desktop 的 `claude_desktop_config.json` 中添加：
```json
{
  "mcpServers": {
    "trustchain": {
      "command": "python",
      "args": ["/path/to/your/mcp_server.py"]
    }
  }
}
```

---

## Merkle 树

用于验证大型文档而无需加载全部内容。

### 使用方法

```python
from trustchain.v2.merkle import MerkleTree, verify_proof

# 100 页的文档
pages = [f"Page {i}: ..." for i in range(100)]

# 构建 Merkle 树
tree = MerkleTree.from_chunks(pages)
print(tree.root)  # 整个文档的单个哈希

# 仅签名根
signed = tc._signer.sign("document", {"merkle_root": tree.root})

# 稍后：仅验证第 42 页
proof = tree.get_proof(42)
is_valid = verify_proof(pages[42], proof, tree.root)
```

### 为什么需要这个？

- RAG 系统：验证来源而无需加载所有文档
- LegalTech：验证合同的单独页面
- IoT：验证大批量中的数据包

---

## CloudEvents

用于与 Kafka 和其他系统集成的标准格式：

```python
from trustchain.v2.events import TrustEvent

# 将 SignedResponse 转换为 CloudEvent
event = TrustEvent.from_signed_response(
    result,
    source="/agent/my-bot/tool/weather"
)

# Kafka 的 JSON
json_str = event.to_json()

# 用于快速过滤的 Kafka 头
headers = event.to_kafka_headers()
```

---

## 审计跟踪 UI

生成用于审计的 HTML 报告：

```python
from trustchain.ui.explorer import ChainExplorer

# 收集操作
chain = [step1, step2, step3, ...]

# 导出为 HTML
explorer = ChainExplorer(chain, tc)
explorer.export_html("audit_report.html")
```

打开交互式报告，包含：
- 操作统计
- 链可视化
- 每个步骤的验证状态

---

## REST API 服务器

TrustChain 可以作为 HTTP 服务器运行：

```bash
uvicorn trustchain.v2.server:app --port 8000
```

端点：
- `POST /sign` -- 签名数据
- `POST /verify` -- 验证签名
- `GET /health` -- 服务器状态
- `GET /public-key` -- 获取公钥

---

## Prometheus 指标

```python
config = TrustChainConfig(enable_metrics=True)
tc = TrustChain(config)
```

可用指标：
- `trustchain_signs_total` -- 签名数量
- `trustchain_verifies_total` -- 验证数量
- `trustchain_sign_seconds` -- 签名时间
- `trustchain_nonce_rejects_total` -- 阻止的重放攻击

---

## 性能

基准测试结果（Apple M1）：

| 操作 | 延迟 | 吞吐量 |
|------|------|--------|
| 签名 | 0.11 ms | 9,102 ops/sec |
| 验证 | 0.22 ms | 4,513 ops/sec |
| 链验证（100 项） | 28 ms | - |
| Merkle（100 页） | 0.18 ms | 5,482 ops/sec |

存储开销：每次操作约 124 字节（88 字节签名 + 36 字节随机数）。

---

## 项目结构

```
trustchain/
  __init__.py          # 主导出
  v2/
    core.py            # TrustChain 类
    signer.py          # 签名和 SignedResponse
    config.py          # 配置
    schemas.py         # OpenAI/Anthropic 模式
    nonce_storage.py   # 内存/Redis 存储
    metrics.py         # Prometheus 指标
    tenants.py         # 多租户
    server.py          # REST API
    verifier.py        # 外部验证
    merkle.py          # Merkle 树
    events.py          # CloudEvents
  integrations/
    langchain.py       # LangChain 适配器
    mcp.py             # MCP 服务器
  ui/
    explorer.py        # HTML 报告
  utils/
    exceptions.py      # 错误
```

---

## 示例

### Jupyter Notebooks

| Notebook | 描述 |
|----------|------|
| [trustchain_tutorial.ipynb](examples/trustchain_tutorial.ipynb) | 基本教程 — 7 个关键场景 |
| [trustchain_advanced.ipynb](examples/trustchain_advanced.ipynb) | 高级 — 密钥持久化、多代理、Redis |
| [trustchain_pro.ipynb](examples/trustchain_pro.ipynb) | 完整 API 参考 v2.1 |

### Python 脚本

在 `examples/` 目录中：

- `mcp_claude_desktop.py` — Claude Desktop 的 MCP 服务器
- `langchain_agent.py` — 与 LangChain 集成
- `secure_rag.py` — 带有 Merkle 树验证的 RAG
- `database_agent.py` — 带有信任链的 SQL 代理
- `api_agent.py` — 带有 CloudEvents 的 HTTP 客户端

---

## 常见问题

**问：这是区块链吗？**
答：不是。这是加密签名，就像 HTTPS 中的签名一样。没有挖矿或共识。

**问：这会减慢代码速度吗？**
答：签名需要 0.11 ms，验证需要 0.22 ms。通常不明显。

**问：我需要 Redis 吗？**
答：开发时不需要（使用内存存储）。生产环境有多台服务器时需要。

**问：可以与任何 AI 一起使用吗？**
答：是的。TrustChain 签名您的函数结果，无论哪个 AI 调用它们。

**问：支持哪些算法？**
答：目前是 Ed25519（快速、安全、128 位安全级别）。

---

## 许可证

MIT 许可证

## 作者

Ed Cherednik

## 版本

2.1.0（2026 年 1 月 19 日）
