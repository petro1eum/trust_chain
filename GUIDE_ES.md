# TrustChain -- Guía del Usuario

## ¿Qué es TrustChain?

TrustChain es una biblioteca Python para la firma criptográfica de respuestas de herramientas de IA. Resuelve el problema de confianza: cuando un agente de IA llama a una función (herramienta), no hay garantía de que el resultado sea real y no una alucinación.

TrustChain añade a cada respuesta:
- Firma criptográfica (Ed25519)
- Nonce único (protección contra ataques de repetición)
- Marca de tiempo
- Opcionalmente: enlace al paso anterior (Cadena de Confianza)

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
old_key = tc.get_key_id()
new_key = tc.rotate_keys()

print(f"Rotación: {old_key[:16]} -> {new_key[:16]}")
```

> ¡Después de la rotación, todas las firmas anteriores se vuelven inválidas!

---

## Rendimiento

Resultados de benchmark (Apple M1):

| Operación | Latencia | Rendimiento |
|-----------|----------|-------------|
| Firmar | 0.11 ms | 9,102 ops/seg |
| Verificar | 0.22 ms | 4,513 ops/seg |

---

## Licencia

MIT

## Autor

Ed Cherednik

## Versión

2.1.0
