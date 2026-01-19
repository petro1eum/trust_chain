# TrustChain -- ユーザーガイド

## TrustChainとは？

TrustChainは、AIツール応答の暗号署名のためのPythonライブラリです。

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

```bash
uv pip install trustchain
```

追加機能：

```bash
uv pip install trustchain[all]  # すべて
```

---

## クイックスタート

```python
from trustchain import TrustChain

tc = TrustChain()

@tc.tool("weather")
def get_weather(city: str) -> dict:
    return {"city": city, "temp": 22}

result = get_weather("東京")
print(result.data)       # {'city': '東京', 'temp': 22}
print(result.signature)  # Ed25519署名

# 検証
is_valid = tc.verify(result)  # True
```

---

## 署名の仕組み

1. データの正規表現を作成（JSON）
2. SHA-256でデータをハッシュ
3. Ed25519秘密鍵でハッシュに署名
4. 署名をBase64でエンコード

---

## リプレイ攻撃防止

```python
tc.verify(result)  # OK -- 初回
tc.verify(result)  # NonceReplayError -- ノンス使用済み
```

---

## 設定

```python
from trustchain import TrustChain, TrustChainConfig

config = TrustChainConfig(
    enable_nonce=True,
    nonce_ttl=86400,
    key_file="keys.json",
)

tc = TrustChain(config)
```

---

## パフォーマンス

| 操作 | レイテンシ |
|------|-----------|
| 署名 | 0.11 ms |
| 検証 | 0.22 ms |

---

## ライセンス

MIT | Ed Cherednik | v2.1.0
