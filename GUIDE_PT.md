# TrustChain -- Guia do Usuário

## O que é TrustChain?

TrustChain é uma biblioteca Python para assinatura criptográfica de respostas de ferramentas de IA. Ela resolve o problema de confiança: quando um agente de IA chama uma função (ferramenta), não há garantia de que o resultado seja real e não uma alucinação.

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

Recomendamos usar **uv** para instalação rápida:

```bash
uv pip install trustchain
```

Ou pip padrão:

```bash
pip install trustchain
```

Funcionalidades adicionais:

```bash
uv pip install trustchain[integrations]  # LangChain + MCP
uv pip install trustchain[ai]            # OpenAI + Anthropic + LangChain
uv pip install trustchain[mcp]           # Apenas servidor MCP
uv pip install trustchain[redis]         # Armazenamento distribuído de nonce
uv pip install trustchain[all]           # Tudo
```

---

## Início Rápido

### Uso Básico

```python
from trustchain import TrustChain

# Criar instância TrustChain
tc = TrustChain()

# Registrar função como ferramenta assinada
@tc.tool("weather")
def get_weather(city: str) -> dict:
    """Obter clima de uma cidade."""
    return {"city": city, "temp": 22, "conditions": "sunny"}

# Chamar função -- obter resposta assinada
result = get_weather("São Paulo")

# result é um objeto SignedResponse
print(result.data)       # {'city': 'São Paulo', 'temp': 22, ...}
print(result.signature)  # Assinatura Ed25519 codificada em Base64
print(result.nonce)      # UUID para proteção contra repetição
```

### Verificação de Assinatura

```python
# Verificar autenticidade da resposta
is_valid = tc.verify(result)
print(is_valid)  # True

# Verificação repetida do mesmo nonce -- erro
try:
    tc.verify(result)
except NonceReplayError:
    print("Ataque de repetição detectado!")
```

---

## Conceitos Principais

### SignedResponse

Quando você chama uma função envolvida com o decorador `@tc.tool()`, ela retorna não dados brutos, mas um objeto `SignedResponse`:

| Campo | Descrição |
|-------|-----------|
| `data` | Resultado da função (qualquer tipo) |
| `signature` | Assinatura Ed25519 em Base64 |
| `signature_id` | ID único de assinatura (UUID) |
| `timestamp` | Timestamp Unix de criação |
| `nonce` | ID único para proteção contra repetição |
| `tool_id` | Identificador da ferramenta |
| `parent_signature` | Link para etapa anterior |

### Como Funciona a Assinatura

1. Representação canônica dos dados criada (JSON)
2. Dados hasheados com SHA-256
3. Hash assinado com chave privada Ed25519
4. Assinatura codificada em Base64

Verificação:
1. Representação canônica restaurada
2. Assinatura decodificada de Base64
3. Chave pública verifica a assinatura

### Proteção Contra Ataques de Repetição

Nonce (Número usado UMA vez) garante que cada resposta só pode ser verificada uma vez.

Cenário de ataque:
```
1. Hacker intercepta resposta "Transferir $100"
2. Hacker envia 100 vezes
3. $10.000 roubados
```

Com TrustChain:
```python
tc.verify(result)  # OK -- primeira vez
tc.verify(result)  # NonceReplayError -- nonce já usado
```

---

## Cadeia de Confiança (Chain of Trust)

Permite vincular criptograficamente múltiplas operações.

### Por que é necessário?

Quando a IA realiza uma tarefa em várias etapas:
1. Busca de dados
2. Análise
3. Geração de relatório

Você precisa provar que a etapa 2 foi realizada com base na etapa 1, não fabricada.

### Uso

```python
from trustchain import TrustChain

tc = TrustChain()

# Etapa 1: Busca (sem pai)
step1 = tc._signer.sign("search", {"query": "balance", "results": [100, 200]})

# Etapa 2: Análise (referencia etapa 1)
step2 = tc._signer.sign(
    "analyze", 
    {"summary": "total=300"},
    parent_signature=step1.signature
)

# Etapa 3: Relatório (referencia etapa 2)
step3 = tc._signer.sign(
    "report",
    {"text": "Balance is 300"},
    parent_signature=step2.signature
)

# Verificar toda a cadeia
chain = [step1, step2, step3]
is_valid = tc.verify_chain(chain)
print(is_valid)  # True -- cadeia intacta
```

### O que verify_chain verifica?

1. Cada assinatura é válida
2. Cada `parent_signature` corresponde à `signature` da etapa anterior
3. A cadeia não está quebrada

---

## Configuração

### Opções Básicas

```python
from trustchain import TrustChain, TrustChainConfig

config = TrustChainConfig(
    algorithm="ed25519",      # Algoritmo de assinatura
    enable_nonce=True,        # Proteção contra repetição
    enable_cache=True,        # Cache de respostas
    cache_ttl=3600,           # Vida útil do cache (segundos)
    nonce_ttl=86400,          # Vida útil do nonce (segundos)
    key_file="keys.json",     # Arquivo de armazenamento de chaves
)

tc = TrustChain(config)
```

### Rotação de Chaves

```python
old_key = tc.get_key_id()
new_key = tc.rotate_keys()

print(f"Rotação: {old_key[:16]} -> {new_key[:16]}")
public_key = tc.export_public_key()
```

> Após a rotação, todas as assinaturas anteriores se tornam inválidas!

### Configuração Distribuída (Redis)

```python
config = TrustChainConfig(
    nonce_backend="redis",
    redis_url="redis://localhost:6379/0",
    nonce_ttl=86400,
)
tc = TrustChain(config)
```

### Multi-Tenancy

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

## Integrações

### OpenAI / Anthropic Schema

```python
schema = tc.get_tool_schema("weather")
schema = tc.get_tool_schema("weather", format="anthropic")
all_schemas = tc.get_tools_schema()
```

### Pydantic V2

```python
from pydantic import BaseModel, Field

class SearchParams(BaseModel):
    query: str = Field(..., description="String de busca")
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

### Servidor MCP (Claude Desktop)

```python
from trustchain.integrations.mcp import serve_mcp
serve_mcp(tc)
```

---

## Árvores Merkle

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

## UI de Auditoria

```python
from trustchain.ui.explorer import ChainExplorer

explorer = ChainExplorer(chain, tc)
explorer.export_html("audit_report.html")
```

---

## Servidor REST API

```bash
uvicorn trustchain.v2.server:app --port 8000
```

---

## Métricas Prometheus

```python
config = TrustChainConfig(enable_metrics=True)
tc = TrustChain(config)
```

---

## Desempenho

| Operação | Latência | Throughput |
|----------|----------|------------|
| Assinar | 0,11 ms | 9.102 ops/seg |
| Verificar | 0,22 ms | 4.513 ops/seg |
| Cadeia (100 itens) | 28 ms | - |
| Merkle (100 páginas) | 0,18 ms | 5.482 ops/seg |

---

## Exemplos

### Jupyter Notebooks

| Notebook | Descrição |
|----------|-----------|
| trustchain_tutorial.ipynb | Tutorial básico |
| trustchain_advanced.ipynb | Avançado |
| trustchain_pro.ipynb | Referência completa da API |

### Scripts Python

- `mcp_claude_desktop.py` — Servidor MCP
- `langchain_agent.py` — Integração LangChain
- `secure_rag.py` — RAG com Merkle
- `database_agent.py` — Agente SQL
- `api_agent.py` — Cliente HTTP

---

## FAQ

**P: Isso é blockchain?**
R: Não. São assinaturas criptográficas, como no HTTPS.

**P: Isso atrasa o código?**
R: Assinar: 0,11 ms, verificar: 0,22 ms. Normalmente imperceptível.

**P: Preciso de Redis?**
R: Para desenvolvimento não. Para produção com múltiplos servidores sim.

**P: Funciona com qualquer IA?**
R: Sim. TrustChain assina os resultados das suas funções.

---

## Licença

MIT License

## Autor

Ed Cherednik

## Versão

2.1.0 (19 de janeiro de 2026)
