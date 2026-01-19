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
```

> Après rotation, toutes les signatures précédentes deviennent invalides !

---

## Performance

Résultats de benchmark (Apple M1) :

| Opération | Latence | Débit |
|-----------|---------|-------|
| Signer | 0,11 ms | 9 102 ops/sec |
| Vérifier | 0,22 ms | 4 513 ops/sec |

---

## Licence

MIT

## Auteur

Ed Cherednik

## Version

2.1.0
