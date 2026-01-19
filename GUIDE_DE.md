# TrustChain -- Benutzerhandbuch

## Was ist TrustChain?

TrustChain ist eine Python-Bibliothek für die kryptografische Signierung von AI-Tool-Antworten. Sie löst das Vertrauensproblem: Wenn ein AI-Agent eine Funktion (Tool) aufruft, gibt es keine Garantie, dass das Ergebnis echt und keine Halluzination ist.

TrustChain fügt jeder Antwort hinzu:
- Kryptografische Signatur (Ed25519)
- Einzigartige Nonce (Schutz vor Replay-Angriffen)
- Zeitstempel
- Optional: Verknüpfung zum vorherigen Schritt (Vertrauenskette)

---

## Voraussetzungen

- **Python 3.10+** (3.13 empfohlen)
- Paketmanager: `uv` (empfohlen) oder `pip`

---

## Installation

Wir empfehlen die Verwendung von **uv** für eine schnelle Installation:

```bash
uv pip install trustchain
```

Oder Standard-pip:

```bash
pip install trustchain
```

Für zusätzliche Funktionen:

```bash
uv pip install trustchain[integrations]  # LangChain + MCP
uv pip install trustchain[ai]            # OpenAI + Anthropic + LangChain
uv pip install trustchain[mcp]           # Nur MCP-Server
uv pip install trustchain[redis]         # Verteilter Nonce-Speicher
uv pip install trustchain[all]           # Alles
```

---

## Schnellstart

### Grundlegende Verwendung

```python
from trustchain import TrustChain

# TrustChain-Instanz erstellen
tc = TrustChain()

# Funktion als signiertes Tool registrieren
@tc.tool("weather")
def get_weather(city: str) -> dict:
    """Wetter für eine Stadt abrufen."""
    return {"city": city, "temp": 22, "conditions": "sunny"}

# Funktion aufrufen -- signierte Antwort erhalten
result = get_weather("Berlin")

# result ist ein SignedResponse-Objekt
print(result.data)       # {'city': 'Berlin', 'temp': 22, ...}
print(result.signature)  # Base64-kodierte Ed25519-Signatur
print(result.nonce)      # UUID für Replay-Schutz
```

### Signaturverifizierung

```python
# Authentizität der Antwort überprüfen
is_valid = tc.verify(result)
print(is_valid)  # True

# Wiederholte Verifizierung derselben Nonce -- Fehler
try:
    tc.verify(result)
except NonceReplayError:
    print("Replay-Angriff erkannt!")
```

---

## Kernkonzepte

### SignedResponse

Wenn Sie eine mit dem `@tc.tool()`-Dekorator umhüllte Funktion aufrufen, gibt sie keine Rohdaten zurück, sondern ein `SignedResponse`-Objekt:

| Feld | Beschreibung |
|------|--------------|
| `data` | Funktionsergebnis (beliebiger Typ) |
| `signature` | Ed25519-Signatur in Base64 |
| `signature_id` | Eindeutige Signatur-ID (UUID) |
| `timestamp` | Unix-Zeitstempel der Erstellung |
| `nonce` | Eindeutige ID für Replay-Schutz |
| `tool_id` | Tool-Kennung |
| `parent_signature` | Verknüpfung zum vorherigen Schritt |

### Wie die Signierung funktioniert

1. Kanonische Datendarstellung wird erstellt (JSON)
2. Daten werden mit SHA-256 gehasht
3. Hash wird mit Ed25519-Privatschlüssel signiert
4. Signatur wird in Base64 kodiert

Verifizierung:
1. Kanonische Darstellung wird wiederhergestellt
2. Signatur wird aus Base64 dekodiert
3. Öffentlicher Schlüssel verifiziert die Signatur

### Schutz vor Replay-Angriffen

Nonce (Nummer, die EINMAL verwendet wird) garantiert, dass jede Antwort nur einmal verifiziert werden kann.

Angriffsszenario:
```
1. Hacker fängt Antwort "Überweise 100$" ab
2. Hacker sendet sie 100 Mal
3. 10.000$ gestohlen
```

Mit TrustChain:
```python
tc.verify(result)  # OK -- erstes Mal
tc.verify(result)  # NonceReplayError -- Nonce bereits verwendet
```

---

## Vertrauenskette (Chain of Trust)

Ermöglicht die kryptografische Verknüpfung mehrerer Operationen.

### Warum ist das erforderlich?

Wenn AI eine mehrstufige Aufgabe ausführt:
1. Datensuche
2. Analyse
3. Berichterstellung

Sie müssen beweisen, dass Schritt 2 auf Basis von Schritt 1 ausgeführt wurde, nicht erfunden.

### Verwendung

```python
from trustchain import TrustChain

tc = TrustChain()

# Schritt 1: Suche (kein Elternteil)
step1 = tc._signer.sign("search", {"query": "balance", "results": [100, 200]})

# Schritt 2: Analyse (referenziert Schritt 1)
step2 = tc._signer.sign(
    "analyze", 
    {"summary": "total=300"},
    parent_signature=step1.signature
)

# Schritt 3: Bericht (referenziert Schritt 2)
step3 = tc._signer.sign(
    "report",
    {"text": "Balance is 300"},
    parent_signature=step2.signature
)

# Gesamte Kette verifizieren
chain = [step1, step2, step3]
is_valid = tc.verify_chain(chain)
print(is_valid)  # True -- Kette intakt
```

### Was prüft verify_chain?

1. Jede Signatur ist gültig
2. Jede `parent_signature` entspricht der `signature` des vorherigen Schritts
3. Kette ist nicht unterbrochen

---

## Konfiguration

### Grundlegende Optionen

```python
from trustchain import TrustChain, TrustChainConfig

config = TrustChainConfig(
    algorithm="ed25519",      # Signaturalgorithmus
    enable_nonce=True,        # Replay-Schutz
    enable_cache=True,        # Antwort-Caching
    cache_ttl=3600,           # Cache-Lebensdauer (Sekunden)
    nonce_ttl=86400,          # Nonce-Lebensdauer (Sekunden)
    key_file="keys.json",     # Schlüsselspeicherdatei
)

tc = TrustChain(config)
```

### Schlüsselrotation

```python
old_key = tc.get_key_id()
new_key = tc.rotate_keys()

print(f"Rotation: {old_key[:16]} -> {new_key[:16]}")
public_key = tc.export_public_key()
```

> Nach der Rotation werden alle vorherigen Signaturen ungültig!

### Verteilte Konfiguration (Redis)

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

## Integrationen

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
    query: str = Field(..., description="Suchzeichenfolge")
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

### MCP-Server (Claude Desktop)

```python
from trustchain.integrations.mcp import serve_mcp
serve_mcp(tc)
```

---

## Merkle-Bäume

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

## Audit-UI

```python
from trustchain.ui.explorer import ChainExplorer

explorer = ChainExplorer(chain, tc)
explorer.export_html("audit_report.html")
```

---

## REST-API-Server

```bash
uvicorn trustchain.v2.server:app --port 8000
```

---

## Prometheus-Metriken

```python
config = TrustChainConfig(enable_metrics=True)
tc = TrustChain(config)
```

---

## Leistung

| Operation | Latenz | Durchsatz |
|-----------|--------|-----------|
| Signieren | 0,11 ms | 9.102 ops/s |
| Verifizieren | 0,22 ms | 4.513 ops/s |
| Kette (100 Elemente) | 28 ms | - |
| Merkle (100 Seiten) | 0,18 ms | 5.482 ops/s |

---

## Beispiele

### Jupyter Notebooks

| Notebook | Beschreibung |
|----------|--------------|
| trustchain_tutorial.ipynb | Grundlegendes Tutorial |
| trustchain_advanced.ipynb | Fortgeschritten |
| trustchain_pro.ipynb | Vollständige API-Referenz |

### Python-Skripte

- `mcp_claude_desktop.py` — MCP-Server
- `langchain_agent.py` — LangChain-Integration
- `secure_rag.py` — RAG mit Merkle
- `database_agent.py` — SQL-Agent
- `api_agent.py` — HTTP-Client

---

## FAQ

**F: Ist das Blockchain?**
A: Nein. Das sind kryptografische Signaturen, wie bei HTTPS.

**F: Verlangsamt das den Code?**
A: Signieren: 0,11 ms, Verifizieren: 0,22 ms. Normalerweise nicht wahrnehmbar.

**F: Brauche ich Redis?**
A: Für Entwicklung nein. Für Produktion mit mehreren Servern ja.

**F: Funktioniert mit jeder KI?**
A: Ja. TrustChain signiert die Ergebnisse Ihrer Funktionen.

---

## Lizenz

MIT License

## Autor

Ed Cherednik

## Version

2.1.0 (19. Januar 2026)
