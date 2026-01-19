# TrustChain -- Guía del Usuario

## ¿Qué es TrustChain?

TrustChain es una biblioteca Python para la firma criptográfica de respuestas de herramientas de IA. Resuelve el problema de confianza: cuando un agente de IA llama a una función (herramienta), no hay garantía de que el resultado sea real y no una alucinación.

TrustChain añade a cada respuesta:
- Firma criptográfica (Ed25519)
- Nonce único (protección contra ataques de repetición)
- Marca de tiempo
- Opcionalmente: enlace al paso anterior (Cadena de Confianza)

![TrustChain Architecture](docs/wiki/architecture_flow.png) (Cadena de Confianza)

---

## Requisitos

- **Python 3.10+** (recomendado 3.13)
- Gestor de paquetes: `uv` (recomendado) o `pip`

---

## Instalación

Recomendamos usar **uv** para una instalación rápida:

```bash
uv pip install trustchain
```

O pip estándar:

```bash
pip install trustchain
```

Para funciones adicionales:

```bash
uv pip install trustchain[integrations]  # LangChain + MCP
uv pip install trustchain[ai]            # OpenAI + Anthropic + LangChain
uv pip install trustchain[mcp]           # Solo servidor MCP
uv pip install trustchain[redis]         # Almacenamiento distribuido de nonce
uv pip install trustchain[all]           # Todo
```

---

## Inicio Rápido

### Uso Básico

```python
from trustchain import TrustChain

# Crear instancia de TrustChain
tc = TrustChain()

# Registrar función como herramienta firmada
@tc.tool("weather")
def get_weather(city: str) -> dict:
    """Obtener el clima de una ciudad."""
    return {"city": city, "temp": 22, "conditions": "sunny"}

# Llamar función -- obtener respuesta firmada
result = get_weather("Madrid")

# result es un objeto SignedResponse
print(result.data)       # {'city': 'Madrid', 'temp': 22, ...}
print(result.signature)  # Firma Ed25519 codificada en Base64
print(result.nonce)      # UUID para protección contra repetición
```

### Verificación de Firma

```python
# Verificar autenticidad de la respuesta
is_valid = tc.verify(result)
print(is_valid)  # True

# Verificación repetida del mismo nonce -- error
try:
    tc.verify(result)
except NonceReplayError:
    print("¡Ataque de repetición detectado!")
```

---

## Conceptos Principales

### SignedResponse

Cuando llamas a una función envuelta con el decorador `@tc.tool()`, no devuelve datos crudos sino un objeto `SignedResponse`:

| Campo | Descripción |
|-------|-------------|
| `data` | Resultado de la función (cualquier tipo) |
| `signature` | Firma Ed25519 en Base64 |
| `signature_id` | ID único de firma (UUID) |
| `timestamp` | Marca de tiempo Unix de creación |
| `nonce` | ID único para protección contra repetición |
| `tool_id` | Identificador de herramienta |
| `parent_signature` | Enlace al paso anterior (Cadena de Confianza) |

### Cómo Funciona la Firma

1. Se crea representación canónica de datos (JSON)
2. Los datos se hashean con SHA-256
3. El hash se firma con clave privada Ed25519
4. La firma se codifica en Base64

Verificación:
1. Se restaura la representación canónica
2. La firma se decodifica de Base64
3. La clave pública verifica la firma

### Protección Contra Ataques de Repetición

Nonce (Número usado UNA vez) garantiza que cada respuesta solo puede verificarse una vez.

Escenario de ataque:
```
1. Hacker intercepta respuesta "Transferir $100"
2. Hacker la envía 100 veces
3. $10,000 robados
```

Con TrustChain:
```python
tc.verify(result)  # OK -- primera vez
tc.verify(result)  # NonceReplayError -- nonce ya usado
```

---

## Cadena de Confianza

Permite enlazar criptográficamente múltiples operaciones.

### ¿Por qué es necesario?

Cuando la IA realiza una tarea de varios pasos:
1. Búsqueda de datos
2. Análisis
3. Generación de informe

Necesitas demostrar que el paso 2 se realizó basándose en el paso 1, no fabricado.

### Uso

```python
from trustchain import TrustChain

tc = TrustChain()

# Paso 1: Búsqueda (sin padre)
step1 = tc._signer.sign("search", {"query": "balance", "results": [100, 200]})

# Paso 2: Análisis (referencia paso 1)
step2 = tc._signer.sign(
    "analyze", 
    {"summary": "total=300"},
    parent_signature=step1.signature  # Enlace al paso anterior
)

# Paso 3: Informe (referencia paso 2)
step3 = tc._signer.sign(
    "report",
    {"text": "Balance is 300"},
    parent_signature=step2.signature
)

# Verificar toda la cadena
chain = [step1, step2, step3]
is_valid = tc.verify_chain(chain)
print(is_valid)  # True -- cadena intacta
```

### ¿Qué verifica verify_chain?

1. Cada firma es válida
2. Cada `parent_signature` coincide con la `signature` del paso anterior
3. La cadena no está rota

---

## Configuración

### Opciones Básicas

```python
from trustchain import TrustChain, TrustChainConfig

config = TrustChainConfig(
    algorithm="ed25519",      # Algoritmo de firma
    enable_nonce=True,        # Protección contra repetición
    enable_cache=True,        # Caché de respuestas
    cache_ttl=3600,           # Vida útil del caché (segundos)
    nonce_ttl=86400,          # Vida útil del nonce (segundos)
    key_file="keys.json",     # Archivo de almacenamiento de claves
)

tc = TrustChain(config)
```

### Rotación de Claves

```python
# Generar nuevas claves
old_key = tc.get_key_id()
new_key = tc.rotate_keys()  # Auto-guarda si key_file está configurado

print(f"Rotación: {old_key[:16]} -> {new_key[:16]}")

# Exportar clave pública para verificación externa
public_key = tc.export_public_key()
```

> ¡Después de la rotación, todas las firmas anteriores se vuelven inválidas!

### Configuración Distribuida (Redis)

Para múltiples servidores:

```python
config = TrustChainConfig(
    nonce_backend="redis",
    redis_url="redis://localhost:6379/0",
    nonce_ttl=86400,
)

tc = TrustChain(config)
```

### Multi-Tenancy

Para SaaS con diferentes clientes:

```python
from trustchain import TenantManager

manager = TenantManager(
    redis_url="redis://localhost:6379",
    key_storage_dir="./keys"  # Dónde almacenar claves de clientes
)

# Obtener TrustChain para cliente específico
tc_acme = manager.get_or_create("acme_corp")
tc_beta = manager.get_or_create("beta_inc")

# Cada cliente tiene sus propias claves
print(tc_acme.get_key_id())  # key-abc123...
print(tc_beta.get_key_id())  # key-xyz789...
```

---

## Integraciones

### OpenAI / Anthropic Schema

TrustChain genera automáticamente JSON Schema para funciones:

```python
# Formato OpenAI
schema = tc.get_tool_schema("weather")

# Formato Anthropic
schema = tc.get_tool_schema("weather", format="anthropic")

# Todas las herramientas a la vez
all_schemas = tc.get_tools_schema()
```

### Pydantic V2

Soporte completo para modelos Pydantic:

```python
from pydantic import BaseModel, Field

class SearchParams(BaseModel):
    query: str = Field(..., description="Cadena de búsqueda")
    limit: int = Field(10, le=100, description="Máximo de resultados")

@tc.tool("search")
def search(params: SearchParams) -> list:
    """Buscar documentos."""
    return []
```

### LangChain

```python
from trustchain.integrations.langchain import to_langchain_tools

lc_tools = to_langchain_tools(tc)

from langchain.agents import AgentExecutor
executor = AgentExecutor(agent=agent, tools=lc_tools)
```

### Servidor MCP (Claude Desktop)

```python
from trustchain.integrations.mcp import serve_mcp

@tc.tool("calculator")
def add(a: int, b: int) -> int:
    return a + b

serve_mcp(tc)
```

---

## Árboles Merkle

Para verificar documentos grandes sin cargar todo el contenido.

```python
from trustchain.v2.merkle import MerkleTree, verify_proof

pages = [f"Page {i}: ..." for i in range(100)]
tree = MerkleTree.from_chunks(pages)

proof = tree.get_proof(42)
is_valid = verify_proof(pages[42], proof, tree.root)
```

---

## CloudEvents

Formato estándar para integración con Kafka:

```python
from trustchain.v2.events import TrustEvent

event = TrustEvent.from_signed_response(result, source="/agent/bot")
json_str = event.to_json()
headers = event.to_kafka_headers()
```

---

## UI de Auditoría

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

Endpoints: `/sign`, `/verify`, `/health`, `/public-key`

---

## Métricas Prometheus

```python
config = TrustChainConfig(enable_metrics=True)
tc = TrustChain(config)
```

---

## Rendimiento

| Operación | Latencia | Rendimiento |
|-----------|----------|-------------|
| Firmar | 0.11 ms | 9,102 ops/seg |
| Verificar | 0.22 ms | 4,513 ops/seg |
| Cadena (100 items) | 28 ms | - |
| Merkle (100 páginas) | 0.18 ms | 5,482 ops/seg |

---

## Ejemplos

### Jupyter Notebooks

| Notebook | Descripción |
|----------|-------------|
| trustchain_tutorial.ipynb | Tutorial básico |
| trustchain_advanced.ipynb | Avanzado |
| trustchain_pro.ipynb | Referencia API completa |

### Scripts Python

- `mcp_claude_desktop.py` — Servidor MCP
- `langchain_agent.py` — Integración LangChain
- `secure_rag.py` — RAG con Merkle
- `database_agent.py` — Agente SQL
- `api_agent.py` — Cliente HTTP

---

## FAQ

**P: ¿Es blockchain?**
R: No. Son firmas criptográficas, como en HTTPS.

**P: ¿Ralentiza el código?**
R: Firmar: 0.11 ms, verificar: 0.22 ms. Normalmente imperceptible.

**P: ¿Necesito Redis?**
R: Para desarrollo no. Para producción con múltiples servidores sí.

**P: ¿Funciona con cualquier IA?**
R: Sí. TrustChain firma los resultados de tus funciones.

---

## Licencia

MIT License

## Autor

Ed Cherednik

## Versión

2.1.0 (19 de enero de 2026)
