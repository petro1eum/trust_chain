# TrustChain -- Guia do Usuário

## O que é TrustChain?

TrustChain é uma biblioteca Python para assinatura criptográfica de respostas de ferramentas de IA.

TrustChain adiciona a cada resposta:
- Assinatura criptográfica (Ed25519)
- Nonce único (proteção contra ataques de repetição)
- Timestamp
- Opcional: link para etapa anterior (Cadeia de Confiança)

---

## Requisitos

- **Python 3.10+** (3.13 recomendado)
- Gerenciador de pacotes: `uv` (recomendado) ou `pip`

---

## Instalação

```bash
uv pip install trustchain
```

Funcionalidades adicionais:

```bash
uv pip install trustchain[all]  # Tudo
```

---

## Início Rápido

```python
from trustchain import TrustChain

tc = TrustChain()

@tc.tool("weather")
def get_weather(city: str) -> dict:
    return {"city": city, "temp": 22}

result = get_weather("São Paulo")
print(result.data)       # {'city': 'São Paulo', 'temp': 22}
print(result.signature)  # Assinatura Ed25519

# Verificar
is_valid = tc.verify(result)  # True
```

---

## Como Funciona a Assinatura

1. Representação canônica dos dados criada (JSON)
2. Dados hasheados com SHA-256
3. Hash assinado com chave privada Ed25519
4. Assinatura codificada em Base64

---

## Proteção Contra Replay

```python
tc.verify(result)  # OK -- primeira vez
tc.verify(result)  # NonceReplayError -- nonce já usado
```

---

## Configuração

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

## Desempenho

| Operação | Latência |
|----------|----------|
| Assinar | 0,11 ms |
| Verificar | 0,22 ms |

---

## Licença

MIT | Ed Cherednik | v2.1.0
