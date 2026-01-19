# TrustChain -- Guide de l'Utilisateur

## Qu'est-ce que TrustChain ?

TrustChain est une bibliothèque Python pour la signature cryptographique des réponses d'outils IA. Elle résout le problème de confiance : lorsqu'un agent IA appelle une fonction (outil), il n'y a aucune garantie que le résultat soit réel et non une hallucination.

TrustChain ajoute à chaque réponse :
- Signature cryptographique (Ed25519)
- Nonce unique (protection contre les attaques par rejeu)
- Horodatage
- Optionnellement : lien vers l'étape précédente (Chaîne de Confiance)

---

## Prérequis

- **Python 3.10+** (3.13 recommandé)
- Gestionnaire de paquets : `uv` (recommandé) ou `pip`

---

## Installation

Nous recommandons d'utiliser **uv** pour une installation rapide :

```bash
uv pip install trustchain
```

Ou pip standard :

```bash
pip install trustchain
```

Pour des fonctionnalités supplémentaires :

```bash
uv pip install trustchain[integrations]  # LangChain + MCP
uv pip install trustchain[ai]            # OpenAI + Anthropic + LangChain
uv pip install trustchain[mcp]           # Serveur MCP uniquement
uv pip install trustchain[redis]         # Stockage distribué de nonce
uv pip install trustchain[all]           # Tout
```

---

## Démarrage Rapide

### Utilisation de Base

```python
from trustchain import TrustChain

# Créer une instance TrustChain
tc = TrustChain()

# Enregistrer une fonction comme outil signé
@tc.tool("weather")
def get_weather(city: str) -> dict:
    """Obtenir la météo d'une ville."""
    return {"city": city, "temp": 22, "conditions": "sunny"}

# Appeler la fonction -- obtenir une réponse signée
result = get_weather("Paris")

# result est un objet SignedResponse
print(result.data)       # {'city': 'Paris', 'temp': 22, ...}
print(result.signature)  # Signature Ed25519 encodée en Base64
print(result.nonce)      # UUID pour la protection contre le rejeu
```

### Vérification de Signature

```python
# Vérifier l'authenticité de la réponse
is_valid = tc.verify(result)
print(is_valid)  # True

# Vérification répétée du même nonce -- erreur
try:
    tc.verify(result)
except NonceReplayError:
    print("Attaque par rejeu détectée !")
```

---

## Concepts Principaux

### SignedResponse

Lorsque vous appelez une fonction enveloppée avec le décorateur `@tc.tool()`, elle retourne non pas des données brutes mais un objet `SignedResponse` :

| Champ | Description |
|-------|-------------|
| `data` | Résultat de la fonction (tout type) |
| `signature` | Signature Ed25519 en Base64 |
| `signature_id` | ID unique de signature (UUID) |
| `timestamp` | Horodatage Unix de création |
| `nonce` | ID unique pour protection contre rejeu |
| `tool_id` | Identifiant de l'outil |
| `parent_signature` | Lien vers l'étape précédente |

### Comment Fonctionne la Signature

1. Représentation canonique des données créée (JSON)
2. Données hachées avec SHA-256
3. Hash signé avec clé privée Ed25519
4. Signature encodée en Base64

Vérification :
1. Représentation canonique restaurée
2. Signature décodée depuis Base64
3. Clé publique vérifie la signature

### Protection Contre les Attaques par Rejeu

Nonce (Nombre utilisé UNE fois) garantit que chaque réponse ne peut être vérifiée qu'une seule fois.

Scénario d'attaque :
```
1. Pirate intercepte la réponse "Transférer 100$"
2. Pirate l'envoie 100 fois
3. 10 000$ volés
```

Avec TrustChain :
```python
tc.verify(result)  # OK -- première fois
tc.verify(result)  # NonceReplayError -- nonce déjà utilisé
```

---

## Chaîne de Confiance

Permet de lier cryptographiquement plusieurs opérations.

### Pourquoi est-ce nécessaire ?

Lorsque l'IA effectue une tâche en plusieurs étapes :
1. Recherche de données
2. Analyse
3. Génération de rapport

Vous devez prouver que l'étape 2 a été effectuée sur la base de l'étape 1, pas fabriquée.

### Utilisation

```python
from trustchain import TrustChain

tc = TrustChain()

# Étape 1 : Recherche (sans parent)
step1 = tc._signer.sign("search", {"query": "balance", "results": [100, 200]})

# Étape 2 : Analyse (référence étape 1)
step2 = tc._signer.sign(
    "analyze", 
    {"summary": "total=300"},
    parent_signature=step1.signature
)

# Étape 3 : Rapport (référence étape 2)
step3 = tc._signer.sign(
    "report",
    {"text": "Balance is 300"},
    parent_signature=step2.signature
)

# Vérifier toute la chaîne
chain = [step1, step2, step3]
is_valid = tc.verify_chain(chain)
print(is_valid)  # True -- chaîne intacte
```

### Que vérifie verify_chain ?

1. Chaque signature est valide
2. Chaque `parent_signature` correspond à la `signature` de l'étape précédente
3. La chaîne n'est pas cassée

---

## Configuration

### Options de Base

```python
from trustchain import TrustChain, TrustChainConfig

config = TrustChainConfig(
    algorithm="ed25519",      # Algorithme de signature
    enable_nonce=True,        # Protection contre rejeu
    enable_cache=True,        # Cache des réponses
    cache_ttl=3600,           # Durée de vie du cache (secondes)
    nonce_ttl=86400,          # Durée de vie du nonce (secondes)
    key_file="keys.json",     # Fichier de stockage des clés
)

tc = TrustChain(config)
```

### Rotation des Clés

```python
old_key = tc.get_key_id()
new_key = tc.rotate_keys()

print(f"Rotation : {old_key[:16]} -> {new_key[:16]}")
public_key = tc.export_public_key()
```

> Après rotation, toutes les signatures précédentes deviennent invalides !

### Configuration Distribuée (Redis)

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

## Intégrations

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
    query: str = Field(..., description="Chaîne de recherche")
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

### Serveur MCP (Claude Desktop)

```python
from trustchain.integrations.mcp import serve_mcp
serve_mcp(tc)
```

---

## Arbres Merkle

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

## UI d'Audit

```python
from trustchain.ui.explorer import ChainExplorer

explorer = ChainExplorer(chain, tc)
explorer.export_html("audit_report.html")
```

---

## Serveur REST API

```bash
uvicorn trustchain.v2.server:app --port 8000
```

---

## Métriques Prometheus

```python
config = TrustChainConfig(enable_metrics=True)
tc = TrustChain(config)
```

---

## Performance

| Opération | Latence | Débit |
|-----------|---------|-------|
| Signer | 0,11 ms | 9 102 ops/sec |
| Vérifier | 0,22 ms | 4 513 ops/sec |
| Chaîne (100 éléments) | 28 ms | - |
| Merkle (100 pages) | 0,18 ms | 5 482 ops/sec |

---

## Exemples

### Jupyter Notebooks

| Notebook | Description |
|----------|-------------|
| trustchain_tutorial.ipynb | Tutoriel de base |
| trustchain_advanced.ipynb | Avancé |
| trustchain_pro.ipynb | Référence API complète |

### Scripts Python

- `mcp_claude_desktop.py` — Serveur MCP
- `langchain_agent.py` — Intégration LangChain
- `secure_rag.py` — RAG avec Merkle
- `database_agent.py` — Agent SQL
- `api_agent.py` — Client HTTP

---

## FAQ

**Q: C'est une blockchain ?**
R: Non. Ce sont des signatures cryptographiques, comme HTTPS.

**Q: Ça ralentit le code ?**
R: Signer : 0,11 ms, vérifier : 0,22 ms. Généralement imperceptible.

**Q: J'ai besoin de Redis ?**
R: Pour le développement non. Pour la production avec plusieurs serveurs oui.

**Q: Ça fonctionne avec n'importe quelle IA ?**
R: Oui. TrustChain signe les résultats de vos fonctions.

---

## Licence

MIT License

## Auteur

Ed Cherednik

## Version

2.1.0 (19 janvier 2026)
