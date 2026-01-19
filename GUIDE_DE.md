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

## Vertrauenskette

Ermöglicht die kryptografische Verknüpfung mehrerer Operationen.

### Warum ist das erforderlich?

Wenn AI eine mehrstufige Aufgabe ausführt:
1. Datensuche
2. Analyse
3. Berichterstellung

Sie müssen beweisen, dass Schritt 2 auf Basis von Schritt 1 ausgeführt wurde, nicht erfunden.

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
```

> Nach der Rotation werden alle vorherigen Signaturen ungültig!

---

## Leistung

Benchmark-Ergebnisse (Apple M1):

| Operation | Latenz | Durchsatz |
|-----------|--------|-----------|
| Signieren | 0,11 ms | 9.102 ops/s |
| Verifizieren | 0,22 ms | 4.513 ops/s |

---

## Lizenz

MIT

## Autor

Ed Cherednik

## Version

2.1.0
