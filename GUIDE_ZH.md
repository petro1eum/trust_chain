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

## 信任链

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

---

## 集成

### MCP 服务器（Claude Desktop）

```python
from trustchain.integrations.mcp import serve_mcp

@tc.tool("calculator")
def add(a: int, b: int) -> int:
    return a + b

# 启动 MCP 服务器
serve_mcp(tc)
```

### LangChain

```python
from trustchain.integrations.langchain import to_langchain_tools

lc_tools = to_langchain_tools(tc)
```

---

## 性能

基准测试结果（Apple M1）：

| 操作 | 延迟 | 吞吐量 |
|------|------|--------|
| 签名 | 0.11 ms | 9,102 ops/sec |
| 验证 | 0.22 ms | 4,513 ops/sec |
| 链验证（100 项） | 28 ms | - |

---

## 许可证

MIT

## 作者

Ed Cherednik

## 版本

2.1.0
