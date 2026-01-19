# TrustChain -- ユーザーガイド

## TrustChainとは？

TrustChainは、AIツール応答の暗号署名のためのPythonライブラリです。信頼性の問題を解決します：AIエージェントが関数（ツール）を呼び出す際、結果が本物であり幻覚ではないことを保証できません。

TrustChainは各応答に以下を追加します：
- 暗号署名（Ed25519）
- 一意のノンス（リプレイ攻撃防止）
- タイムスタンプ
- オプション：前のステップへのリンク（トラストチェーン）

---

## 要件

- **Python 3.10+**（3.13推奨）
- パッケージマネージャー：`uv`（推奨）または `pip`

---

## インストール

高速インストールには**uv**の使用を推奨します：

```bash
uv pip install trustchain
```

または標準pip：

```bash
pip install trustchain
```

追加機能：

```bash
uv pip install trustchain[integrations]  # LangChain + MCP
uv pip install trustchain[ai]            # OpenAI + Anthropic + LangChain
uv pip install trustchain[mcp]           # MCPサーバーのみ
uv pip install trustchain[redis]         # 分散ノンスストレージ
uv pip install trustchain[all]           # すべて
```

---

## クイックスタート

### 基本的な使用法

```python
from trustchain import TrustChain

# TrustChainインスタンスを作成
tc = TrustChain()

# 関数を署名付きツールとして登録
@tc.tool("weather")
def get_weather(city: str) -> dict:
    """都市の天気を取得します。"""
    return {"city": city, "temp": 22, "conditions": "sunny"}

# 関数を呼び出し -- 署名付き応答を取得
result = get_weather("東京")

# resultはSignedResponseオブジェクト
print(result.data)       # {'city': '東京', 'temp': 22, ...}
print(result.signature)  # Base64エンコードされたEd25519署名
print(result.nonce)      # リプレイ保護用UUID
```

### 署名検証

```python
# 応答の真正性を確認
is_valid = tc.verify(result)
print(is_valid)  # True

# 同じノンスの再検証 -- エラー
try:
    tc.verify(result)
except NonceReplayError:
    print("リプレイ攻撃を検出！")
```

---

## コアコンセプト

### SignedResponse

`@tc.tool()`デコレータでラップされた関数を呼び出すと、生データではなく`SignedResponse`オブジェクトが返されます：

| フィールド | 説明 |
|-----------|------|
| `data` | 関数の結果（任意の型） |
| `signature` | Base64形式のEd25519署名 |
| `signature_id` | 一意の署名ID（UUID） |
| `timestamp` | 作成時のUnixタイムスタンプ |
| `nonce` | リプレイ保護用の一意ID |
| `tool_id` | ツール識別子 |
| `parent_signature` | 前のステップへのリンク |

### 署名の仕組み

1. データの正規表現を作成（JSON）
2. SHA-256でデータをハッシュ
3. Ed25519秘密鍵でハッシュに署名
4. 署名をBase64でエンコード

検証：
1. 正規表現を復元
2. Base64から署名をデコード
3. 公開鍵で署名を検証

### リプレイ攻撃防止

ノンス（一度だけ使用される数値）は、各応答が一度だけ検証できることを保証します。

攻撃シナリオ：
```
1. ハッカーが「$100を送金」の応答を傍受
2. ハッカーが100回送信
3. $10,000が盗まれる
```

TrustChain使用時：
```python
tc.verify(result)  # OK -- 初回
tc.verify(result)  # NonceReplayError -- ノンス使用済み
```

---

## トラストチェーン（Chain of Trust）

複数の操作を暗号的にリンクできます。

### なぜ必要？

AIが複数ステップのタスクを実行する場合：
1. データ検索
2. 分析
3. レポート生成

ステップ2がステップ1に基づいて実行され、捏造されていないことを証明する必要があります。

### 使用法

```python
from trustchain import TrustChain

tc = TrustChain()

# ステップ1：検索（親なし）
step1 = tc._signer.sign("search", {"query": "balance", "results": [100, 200]})

# ステップ2：分析（ステップ1を参照）
step2 = tc._signer.sign(
    "analyze", 
    {"summary": "total=300"},
    parent_signature=step1.signature
)

# ステップ3：レポート（ステップ2を参照）
step3 = tc._signer.sign(
    "report",
    {"text": "Balance is 300"},
    parent_signature=step2.signature
)

# チェーン全体を検証
chain = [step1, step2, step3]
is_valid = tc.verify_chain(chain)
print(is_valid)  # True -- チェーン完全
```

### verify_chainは何をチェック？

1. 各署名が有効
2. 各`parent_signature`が前のステップの`signature`と一致
3. チェーンが途切れていない

---

## 設定

### 基本オプション

```python
from trustchain import TrustChain, TrustChainConfig

config = TrustChainConfig(
    algorithm="ed25519",      # 署名アルゴリズム
    enable_nonce=True,        # リプレイ攻撃保護
    enable_cache=True,        # 応答キャッシング
    cache_ttl=3600,           # キャッシュ有効期間（秒）
    nonce_ttl=86400,          # ノンス有効期間（秒）
    key_file="keys.json",     # 鍵保存ファイル
)

tc = TrustChain(config)
```

### 鍵ローテーション

```python
old_key = tc.get_key_id()
new_key = tc.rotate_keys()

print(f"ローテーション: {old_key[:16]} -> {new_key[:16]}")
public_key = tc.export_public_key()
```

> ローテーション後、以前のすべての署名が無効になります！

### 分散設定（Redis）

```python
config = TrustChainConfig(
    nonce_backend="redis",
    redis_url="redis://localhost:6379/0",
    nonce_ttl=86400,
)
tc = TrustChain(config)
```

### マルチテナンシー

```python
from trustchain import TenantManager

manager = TenantManager(
    redis_url="redis://localhost:6379",
    key_storage_dir="./keys"
)

tc_acme = manager.get_or_create("acme_corp")
tc_beta = manager.get_or_create("beta_inc")
```

---

## 統合

### OpenAI / Anthropic スキーマ

```python
schema = tc.get_tool_schema("weather")
schema = tc.get_tool_schema("weather", format="anthropic")
all_schemas = tc.get_tools_schema()
```

### Pydantic V2

```python
from pydantic import BaseModel, Field

class SearchParams(BaseModel):
    query: str = Field(..., description="検索クエリ文字列")
    limit: int = Field(10, le=100)

@tc.tool("search")
def search(params: SearchParams) -> list:
    return []
```

### LangChain

```python
from trustchain.integrations.langchain import to_langchain_tools
lc_tools = to_langchain_tools(tc)
```

### MCPサーバー（Claude Desktop）

```python
from trustchain.integrations.mcp import serve_mcp
serve_mcp(tc)
```

---

## Merkleツリー

```python
from trustchain.v2.merkle import MerkleTree, verify_proof

pages = [f"Page {i}: ..." for i in range(100)]
tree = MerkleTree.from_chunks(pages)

proof = tree.get_proof(42)
is_valid = verify_proof(pages[42], proof, tree.root)
```

---

## CloudEvents

```python
from trustchain.v2.events import TrustEvent

event = TrustEvent.from_signed_response(result, source="/agent/bot")
json_str = event.to_json()
```

---

## 監査UI

```python
from trustchain.ui.explorer import ChainExplorer

explorer = ChainExplorer(chain, tc)
explorer.export_html("audit_report.html")
```

---

## REST APIサーバー

```bash
uvicorn trustchain.v2.server:app --port 8000
```

---

## Prometheusメトリクス

```python
config = TrustChainConfig(enable_metrics=True)
tc = TrustChain(config)
```

---

## パフォーマンス

| 操作 | レイテンシ | スループット |
|------|-----------|-------------|
| 署名 | 0.11 ms | 9,102 ops/秒 |
| 検証 | 0.22 ms | 4,513 ops/秒 |
| チェーン検証（100項目） | 28 ms | - |
| Merkle（100ページ） | 0.18 ms | 5,482 ops/秒 |

---

## 例

### Jupyter Notebooks

| Notebook | 説明 |
|----------|------|
| trustchain_tutorial.ipynb | 基本チュートリアル |
| trustchain_advanced.ipynb | 上級 |
| trustchain_pro.ipynb | 完全なAPI参照 |

### Pythonスクリプト

- `mcp_claude_desktop.py` — MCPサーバー
- `langchain_agent.py` — LangChain統合
- `secure_rag.py` — Merkleを使用したRAG
- `database_agent.py` — SQLエージェント
- `api_agent.py` — HTTPクライアント

---

## FAQ

**Q: これはブロックチェーンですか？**
A: いいえ。HTTPSと同様の暗号署名です。

**Q: コードが遅くなりますか？**
A: 署名：0.11 ms、検証：0.22 ms。通常は気づかない程度です。

**Q: Redisが必要ですか？**
A: 開発用には不要です。複数サーバーの本番環境では必要です。

**Q: どのAIでも動作しますか？**
A: はい。TrustChainは関数の結果に署名します。

---

## ライセンス

MIT License

## 作者

Ed Cherednik

## バージョン

2.1.0（2026年1月19日）
