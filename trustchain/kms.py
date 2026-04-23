"""Pluggable key management for TrustChain (enterprise, ADR-SEC-002).

Provides a minimal ``KeyProvider`` protocol and two built-in adapters:

* :class:`LocalFileKeyProvider` — JSON file on disk (default OSS experience,
  and a baseline for on-prem deployments).
* :class:`EnvVarKeyProvider` — base64-encoded JSON in an environment variable
  (12-factor / container-friendly).

The protocol intentionally mirrors what ``trustchain_pro.enterprise.kms``
exports, so Pro-grade providers (AWS KMS, Azure Key Vault, HSM) satisfy the
same interface. Enterprise users can wire those in via
``TrustChainConfig(key_provider=...)`` without forking the OSS core.

Design goals
------------
1. **No hard fork.** OSS can run with file-based keys; Pro can supply a
   cloud provider; both pass the same ``assert isinstance(..., KeyProvider)``
   contract.
2. **Seed vs signature boundary.** ``get_seed()`` returns raw Ed25519 seed
   bytes for soft-KMS setups (files, env, Vault KV).  ``sign(data)`` is the
   hard-KMS path where the private key **never leaves** the HSM/KMS.
3. **Audit hooks.** ``export_metadata()`` returns non-secret provenance
   (provider name, key_id, URI, creation time) — logged at startup so
   operators can verify that the expected key is in use.
"""

from __future__ import annotations

import base64
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

# ── Protocol / metadata ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class KeyProviderMetadata:
    """Non-secret provenance, safe to log / include in health endpoints."""

    provider: str
    key_id: str
    algorithm: str = "ed25519"
    uri: str | None = None
    created_at: float = 0.0


@runtime_checkable
class KeyProvider(Protocol):
    """Protocol for external key management providers.

    Implementations fall into two categories:

    * **Soft KMS** (file/env/Vault KV): ``get_seed()`` returns 32-byte Ed25519
      private seed; the signer holds the key in-process.
    * **Hard KMS / HSM** (AWS KMS, Azure KeyVault, PKCS#11): ``get_seed()``
      raises ``KeyProviderError``; the signer must call ``sign()`` /
      ``verify()`` directly — the key never enters the process.
    """

    def get_metadata(self) -> KeyProviderMetadata: ...

    def get_public_key(self) -> bytes:
        """Raw Ed25519 public key (32 bytes)."""
        ...

    def get_key_id(self) -> str: ...

    def get_seed(self) -> bytes:
        """Raw Ed25519 private seed (32 bytes).  Hard-KMS impls raise."""
        ...

    def sign(self, data: bytes) -> bytes:
        """Produce Ed25519 signature over ``data``.  Hard-KMS path."""
        ...

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify Ed25519 signature.  Always available, even for hard-KMS."""
        ...


class KeyProviderError(Exception):
    pass


# ── Default in-process Ed25519 signer (shared helper) ─────────────────────────


def _signer_from_seed(seed: bytes):
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as e:  # pragma: no cover
        raise KeyProviderError("cryptography package is required") from e
    if len(seed) != 32:
        raise KeyProviderError(f"Ed25519 seed must be 32 bytes, got {len(seed)}")
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def _raw_pub(priv) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _raw_priv(priv) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ── LocalFileKeyProvider ─────────────────────────────────────────────────────


class LocalFileKeyProvider:
    """Soft-KMS: keys as JSON on disk.

    File format (matches ``Signer.export_keys``)::

        {
          "type": "ed25519",
          "key_id": "<uuid>",
          "private_key": "<base64 raw seed, 32 bytes>",
          "algorithm": "ed25519"
        }

    If the file does not exist, a new key is generated and persisted on first
    use, so this provider is drop-in compatible with the historical
    ``TrustChainConfig.key_file`` behaviour.
    """

    def __init__(self, path: str | os.PathLike, *, auto_create: bool = True) -> None:
        self._path = Path(path).expanduser()
        self._auto_create = auto_create
        self._load_or_create()

    def _load_or_create(self) -> None:
        if self._path.exists():
            data = json.loads(self._path.read_text("utf-8"))
            if data.get("algorithm", "ed25519") != "ed25519":
                raise KeyProviderError(f"unsupported algorithm in {self._path}")
            self._key_id = data.get("key_id") or str(uuid.uuid4())
            self._seed = base64.b64decode(data["private_key"])
            self._created_at = float(data.get("created_at", time.time()))
        else:
            if not self._auto_create:
                raise KeyProviderError(f"key file not found: {self._path}")
            try:
                from cryptography.hazmat.primitives.asymmetric import ed25519
            except ImportError as e:  # pragma: no cover
                raise KeyProviderError("cryptography package is required") from e
            priv = ed25519.Ed25519PrivateKey.generate()
            self._seed = _raw_priv(priv)
            self._key_id = str(uuid.uuid4())
            self._created_at = time.time()
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(
                    {
                        "type": "ed25519",
                        "key_id": self._key_id,
                        "private_key": base64.b64encode(self._seed).decode("ascii"),
                        "algorithm": "ed25519",
                        "created_at": self._created_at,
                    },
                    indent=2,
                ),
                "utf-8",
            )
            try:
                self._path.chmod(0o600)
            except OSError:
                pass
        self._priv = _signer_from_seed(self._seed)
        self._pub_raw = _raw_pub(self._priv)

    def get_metadata(self) -> KeyProviderMetadata:
        return KeyProviderMetadata(
            provider="local-file",
            key_id=self._key_id,
            algorithm="ed25519",
            uri=str(self._path),
            created_at=self._created_at,
        )

    def get_public_key(self) -> bytes:
        return self._pub_raw

    def get_key_id(self) -> str:
        return self._key_id

    def get_seed(self) -> bytes:
        return self._seed

    def sign(self, data: bytes) -> bytes:
        return self._priv.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519

            pub = ed25519.Ed25519PublicKey.from_public_bytes(self._pub_raw)
            pub.verify(signature, data)
            return True
        except Exception:
            return False


# ── EnvVarKeyProvider ─────────────────────────────────────────────────────────


class EnvVarKeyProvider:
    """Soft-KMS: private key material pulled from an env var (12-factor).

    Expected env value is base64-encoded JSON identical to the on-disk format::

        TC_PRIVATE_KEY=$(python -c 'import base64,json,os; \\
            print(base64.b64encode(json.dumps({...}).encode()).decode())')

    The value is parsed once at construction; rotation requires process restart
    (by design — env vars are immutable in enterprise scheduler contracts).
    """

    def __init__(self, env_var: str, *, value: str | None = None) -> None:
        self._env_var = env_var
        raw = value if value is not None else os.environ.get(env_var)
        if not raw:
            raise KeyProviderError(f"environment variable {env_var!r} is not set")
        try:
            data = json.loads(base64.b64decode(raw).decode("utf-8"))
        except Exception as e:
            raise KeyProviderError(f"invalid base64/JSON in ${env_var}: {e}") from e
        if data.get("algorithm", "ed25519") != "ed25519":
            raise KeyProviderError(f"unsupported algorithm in ${env_var}")
        self._key_id = data.get("key_id") or str(uuid.uuid4())
        self._seed = base64.b64decode(data["private_key"])
        self._created_at = float(data.get("created_at", time.time()))
        self._priv = _signer_from_seed(self._seed)
        self._pub_raw = _raw_pub(self._priv)

    def get_metadata(self) -> KeyProviderMetadata:
        return KeyProviderMetadata(
            provider="env-var",
            key_id=self._key_id,
            algorithm="ed25519",
            uri=f"env:{self._env_var}",
            created_at=self._created_at,
        )

    def get_public_key(self) -> bytes:
        return self._pub_raw

    def get_key_id(self) -> str:
        return self._key_id

    def get_seed(self) -> bytes:
        return self._seed

    def sign(self, data: bytes) -> bytes:
        return self._priv.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519

            pub = ed25519.Ed25519PublicKey.from_public_bytes(self._pub_raw)
            pub.verify(signature, data)
            return True
        except Exception:
            return False


# ── VaultTransitKeyProvider (hard-KMS: HashiCorp Vault Transit, Ed25519) ─────


class VaultTransitKeyProvider:
    """Hard-KMS provider backed by HashiCorp Vault Transit engine.

    HashiCorp Vault Transit — одно из немногих enterprise-решений, нативно
    поддерживающих Ed25519 (``type=ed25519`` на create-key). Приватный ключ
    **никогда не покидает Vault**: ``sign()`` отправляет данные в Vault,
    возвращается подпись. Это настоящий «hard-KMS» путь, как и CloudHSM /
    AWS KMS ECDSA.

    Использование
    -------------

    Установите key-material в Vault один раз::

        vault secrets enable transit
        vault write -f transit/keys/trustchain-agent type=ed25519 exportable=false

    Передайте провайдер в конфиг::

        from trustchain import TrustChainConfig, VaultTransitKeyProvider

        kp = VaultTransitKeyProvider(
            url=os.environ["VAULT_ADDR"],
            token=os.environ["VAULT_TOKEN"],
            key_name="trustchain-agent",
        )
        tc = TrustChain(TrustChainConfig(key_provider=kp))

    ``get_seed()`` всегда бросает ``KeyProviderError`` — это hard-KMS контракт;
    сервис/клиент обязан использовать ``sign()`` / ``verify()``.

    Ротация ключа: Vault хранит versioned keys (v1, v2, ...).
    ``get_key_id()`` возвращает ``"{key_name}:v{version}"`` — пишется в
    ``metadata.key_id`` каждого подписанного ответа, чтобы auditor мог
    развязать rotation events в append-only log.
    """

    def __init__(
        self,
        *,
        url: str,
        token: str,
        key_name: str,
        mount_point: str = "transit",
        namespace: str | None = None,
        verify_tls: bool | str = True,
    ) -> None:
        try:
            import hvac  # type: ignore
        except ImportError as e:  # pragma: no cover
            raise KeyProviderError(
                "VaultTransitKeyProvider requires `hvac`; "
                "install trustchain[vault] or pip install hvac"
            ) from e

        self._mount_point = mount_point
        self._key_name = key_name
        client = hvac.Client(
            url=url, token=token, namespace=namespace, verify=verify_tls
        )
        if not client.is_authenticated():
            raise KeyProviderError("Vault authentication failed (token invalid?)")
        self._client = client

        # Read key metadata / public key. Vault returns all versions; мы
        # фиксируем latest_version как «текущий».
        meta = client.secrets.transit.read_key(name=key_name, mount_point=mount_point)[
            "data"
        ]
        if meta.get("type") != "ed25519":
            raise KeyProviderError(
                f"Vault Transit key {key_name!r} is {meta.get('type')}, "
                "expected ed25519"
            )
        self._latest_version = int(meta["latest_version"])
        # Vault returns pem/base64 public key per version.
        pub_entry = meta["keys"][str(self._latest_version)]
        pub_b64 = (
            pub_entry.get("public_key") if isinstance(pub_entry, dict) else pub_entry
        )
        if not pub_b64:
            raise KeyProviderError(
                f"Vault did not return public_key for {key_name} v{self._latest_version}"
            )
        try:
            self._pub_raw = base64.b64decode(pub_b64)
        except Exception as e:
            raise KeyProviderError(f"invalid base64 public_key: {e}") from e
        if len(self._pub_raw) != 32:
            raise KeyProviderError(
                f"Ed25519 public key must be 32 bytes, got {len(self._pub_raw)}"
            )
        self._created_at = float(meta.get("min_decryption_version", 0)) or time.time()
        self._key_id = f"{key_name}:v{self._latest_version}"
        self._url = url

    def get_metadata(self) -> KeyProviderMetadata:
        return KeyProviderMetadata(
            provider="vault-transit",
            key_id=self._key_id,
            algorithm="ed25519",
            uri=f"{self._url}/v1/{self._mount_point}/keys/{self._key_name}",
            created_at=self._created_at,
        )

    def get_public_key(self) -> bytes:
        return self._pub_raw

    def get_key_id(self) -> str:
        return self._key_id

    def get_seed(self) -> bytes:
        # Hard-KMS: приватный seed недоступен клиенту by design.
        raise KeyProviderError(
            "VaultTransitKeyProvider is a hard-KMS provider — private seed "
            "never leaves Vault. Use sign()/verify() instead."
        )

    def sign(self, data: bytes) -> bytes:
        resp = self._client.secrets.transit.sign_data(
            name=self._key_name,
            hash_input=base64.b64encode(data).decode("ascii"),
            mount_point=self._mount_point,
            # Ed25519 не требует pre-hash.
            hash_algorithm="sha2-256",
            marshaling_algorithm="asn1",
        )
        sig_str = resp["data"]["signature"]  # формат: "vault:v1:<base64>"
        try:
            _, _, b64 = sig_str.split(":", 2)
        except ValueError as e:
            raise KeyProviderError(
                f"Vault returned malformed signature: {sig_str}"
            ) from e
        return base64.b64decode(b64)

    def verify(self, data: bytes, signature: bytes) -> bool:
        # Локальная верификация по public key — быстрее и не требует RTT в Vault.
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519

            pub = ed25519.Ed25519PublicKey.from_public_bytes(self._pub_raw)
            pub.verify(signature, data)
            return True
        except Exception:
            return False


# ── AwsSecretsManagerKeyProvider (soft-KMS via AWS, envelope-encrypted) ──────


class AwsSecretsManagerKeyProvider:
    """Soft-KMS provider: Ed25519 seed stored in AWS Secrets Manager.

    AWS KMS нативно **не поддерживает** Ed25519 (только ECDSA P-256 / P-384 /
    P-521 и RSA). Для Ed25519 на AWS мы используем Secrets Manager: seed
    шифруется AWS KMS CMK at-rest, достаётся в процесс один раз при старте,
    дальше работаем как обычный soft-KMS.

    Это всё ещё в разы лучше, чем ``key_file=~/.trustchain/key.json``:

    * Ротация ключа централизована (AWS Secrets Manager Rotation Lambda).
    * Доступ контролируется IAM (``secretsmanager:GetSecretValue``), не FS.
    * CloudTrail логирует каждую выдачу ``GetSecretValue`` — auditor-friendly.
    * Envelope encryption: без дешифровки AWS KMS CMK значение бесполезно.

    Для **hard-KMS** на AWS нужен CloudHSM + PKCS#11 (Ed25519 via PKCS#11 v3).
    """

    def __init__(
        self,
        *,
        secret_id: str,
        region_name: str | None = None,
        client: object | None = None,
    ) -> None:
        if client is None:
            try:
                import boto3  # type: ignore
            except ImportError as e:  # pragma: no cover
                raise KeyProviderError(
                    "AwsSecretsManagerKeyProvider requires `boto3`; "
                    "install trustchain[aws] or pip install boto3"
                ) from e
            client = boto3.client("secretsmanager", region_name=region_name)
        self._secret_id = secret_id
        self._client = client

        resp = client.get_secret_value(SecretId=secret_id)  # type: ignore[attr-defined]
        payload = resp.get("SecretString") or base64.b64decode(
            resp.get("SecretBinary", b"")
        ).decode("utf-8")
        try:
            data = json.loads(payload)
        except Exception as e:
            raise KeyProviderError(
                f"Secret {secret_id!r} is not valid JSON: {e}"
            ) from e
        if data.get("algorithm", "ed25519") != "ed25519":
            raise KeyProviderError(f"unsupported algorithm in secret {secret_id!r}")
        self._seed = base64.b64decode(data["private_key"])
        self._key_id = data.get("key_id") or resp.get("VersionId") or str(uuid.uuid4())
        self._created_at = float(data.get("created_at", time.time()))
        self._priv = _signer_from_seed(self._seed)
        self._pub_raw = _raw_pub(self._priv)

    def get_metadata(self) -> KeyProviderMetadata:
        return KeyProviderMetadata(
            provider="aws-secrets-manager",
            key_id=self._key_id,
            algorithm="ed25519",
            uri=f"aws-secretsmanager:{self._secret_id}",
            created_at=self._created_at,
        )

    def get_public_key(self) -> bytes:
        return self._pub_raw

    def get_key_id(self) -> str:
        return self._key_id

    def get_seed(self) -> bytes:
        return self._seed

    def sign(self, data: bytes) -> bytes:
        return self._priv.sign(data)

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519

            pub = ed25519.Ed25519PublicKey.from_public_bytes(self._pub_raw)
            pub.verify(signature, data)
            return True
        except Exception:
            return False


__all__ = [
    "AwsSecretsManagerKeyProvider",
    "EnvVarKeyProvider",
    "KeyProvider",
    "KeyProviderError",
    "KeyProviderMetadata",
    "LocalFileKeyProvider",
    "VaultTransitKeyProvider",
]
