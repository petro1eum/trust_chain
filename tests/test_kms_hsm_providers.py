"""Real HSM / cloud KMS key providers (ADR-SEC-002 §HSM).

Проверяем:

* ``AwsSecretsManagerKeyProvider`` — soft-KMS через AWS Secrets Manager
  (seed зашифрован AWS KMS CMK at-rest, mock через ``moto``).
* ``VaultTransitKeyProvider`` — hard-KMS через HashiCorp Vault Transit
  engine. Здесь мы подделываем ``hvac.Client`` моком, чтобы избежать
  зависимости от реального Vault dev-server в обычном CI.
* Интеграция оба провайдера ↔ ``TrustChainConfig.key_provider`` (sign/verify).
"""

from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock, patch

import pytest

from trustchain.kms import (
    AwsSecretsManagerKeyProvider,
    KeyProvider,
    KeyProviderError,
    VaultTransitKeyProvider,
)

# ── AWS Secrets Manager (moto) ───────────────────────────────────────────────

moto = pytest.importorskip("moto")


def _make_ed25519_secret_payload() -> dict:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return {
        "algorithm": "ed25519",
        "key_id": "aws-test-key-1",
        "private_key": base64.b64encode(seed).decode("ascii"),
        "created_at": 1700_000_000.0,
    }


@pytest.fixture
def aws_secret_client():
    import boto3
    from moto import mock_aws

    with mock_aws():
        client = boto3.client("secretsmanager", region_name="us-east-1")
        payload = _make_ed25519_secret_payload()
        client.create_secret(
            Name="trustchain/agent-key", SecretString=json.dumps(payload)
        )
        yield client, payload


class TestAwsSecretsManagerKeyProvider:
    def test_load_from_moto_secret(self, aws_secret_client):
        client, _ = aws_secret_client
        provider = AwsSecretsManagerKeyProvider(
            secret_id="trustchain/agent-key", client=client
        )
        assert isinstance(provider, KeyProvider)
        md = provider.get_metadata()
        assert md.provider == "aws-secrets-manager"
        assert md.algorithm == "ed25519"
        assert "trustchain/agent-key" in (md.uri or "")
        assert len(provider.get_public_key()) == 32

    def test_sign_verify_roundtrip(self, aws_secret_client):
        client, _ = aws_secret_client
        provider = AwsSecretsManagerKeyProvider(
            secret_id="trustchain/agent-key", client=client
        )
        data = b"enterprise payload"
        sig = provider.sign(data)
        assert provider.verify(data, sig) is True
        assert provider.verify(data + b"X", sig) is False

    def test_missing_secret_raises(self, aws_secret_client):
        client, _ = aws_secret_client
        with pytest.raises(Exception):  # noqa: B017 — ResourceNotFoundException wrapped
            AwsSecretsManagerKeyProvider(secret_id="nope", client=client)

    def test_bad_algorithm_rejected(self, aws_secret_client):
        client, _ = aws_secret_client
        client.create_secret(
            Name="bad/algo",
            SecretString=json.dumps(
                {
                    "algorithm": "rsa",
                    "private_key": base64.b64encode(b"x" * 32).decode(),
                }
            ),
        )
        with pytest.raises(KeyProviderError, match="unsupported algorithm"):
            AwsSecretsManagerKeyProvider(secret_id="bad/algo", client=client)


# ── Vault Transit (mocked hvac.Client) ───────────────────────────────────────


def _mock_vault_client(pub_raw: bytes, latest_version: int = 1) -> MagicMock:
    """Фейковый hvac.Client со статической Ed25519 key version."""
    mock = MagicMock()
    mock.is_authenticated.return_value = True
    mock.secrets.transit.read_key.return_value = {
        "data": {
            "type": "ed25519",
            "latest_version": latest_version,
            "min_decryption_version": 1,
            "keys": {
                str(latest_version): {
                    "public_key": base64.b64encode(pub_raw).decode("ascii"),
                }
            },
        }
    }
    return mock


class TestVaultTransitKeyProvider:
    def test_requires_authentication(self):
        with patch("hvac.Client") as mock_cls:
            mock = MagicMock()
            mock.is_authenticated.return_value = False
            mock_cls.return_value = mock
            with pytest.raises(KeyProviderError, match="authentication failed"):
                VaultTransitKeyProvider(
                    url="http://vault:8200",
                    token="root",
                    key_name="trustchain",
                )

    def test_read_ed25519_key_metadata(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        priv = ed25519.Ed25519PrivateKey.generate()
        pub_raw = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        with patch("hvac.Client") as mock_cls:
            mock_cls.return_value = _mock_vault_client(pub_raw, latest_version=3)
            provider = VaultTransitKeyProvider(
                url="http://vault:8200",
                token="root",
                key_name="trustchain-agent",
            )
        md = provider.get_metadata()
        assert md.provider == "vault-transit"
        assert md.key_id == "trustchain-agent:v3"
        assert provider.get_public_key() == pub_raw

    def test_rejects_non_ed25519_key(self):
        with patch("hvac.Client") as mock_cls:
            mock = MagicMock()
            mock.is_authenticated.return_value = True
            mock.secrets.transit.read_key.return_value = {
                "data": {
                    "type": "aes256-gcm96",
                    "latest_version": 1,
                    "keys": {"1": {}},
                }
            }
            mock_cls.return_value = mock
            with pytest.raises(KeyProviderError, match="expected ed25519"):
                VaultTransitKeyProvider(
                    url="http://vault:8200",
                    token="root",
                    key_name="aes-key",
                )

    def test_seed_never_leaves_vault(self):
        """Hard-KMS контракт: get_seed() обязан бросать KeyProviderError."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        priv = ed25519.Ed25519PrivateKey.generate()
        pub_raw = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        with patch("hvac.Client") as mock_cls:
            mock_cls.return_value = _mock_vault_client(pub_raw)
            provider = VaultTransitKeyProvider(
                url="http://vault:8200", token="root", key_name="k"
            )
        with pytest.raises(KeyProviderError, match="hard-KMS"):
            provider.get_seed()

    def test_sign_calls_vault_transit_sign(self):
        """sign() → POST /v1/transit/sign/<key>; ответ формата vault:v1:<b64sig>."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        priv = ed25519.Ed25519PrivateKey.generate()
        pub_raw = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        # Создаём настоящую подпись, чтобы verify() прошёл
        data = b"sign-me"
        sig_bytes = priv.sign(data)

        with patch("hvac.Client") as mock_cls:
            mock = _mock_vault_client(pub_raw)
            mock.secrets.transit.sign_data.return_value = {
                "data": {
                    "signature": "vault:v1:"
                    + base64.b64encode(sig_bytes).decode("ascii"),
                }
            }
            mock_cls.return_value = mock
            provider = VaultTransitKeyProvider(
                url="http://vault:8200", token="root", key_name="k"
            )
            out = provider.sign(data)
        assert out == sig_bytes
        assert provider.verify(data, out) is True
        # local tamper → verify fails; sign() не вызывается повторно
        assert provider.verify(b"other", out) is False

    def test_malformed_signature_raises(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        priv = ed25519.Ed25519PrivateKey.generate()
        pub_raw = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        with patch("hvac.Client") as mock_cls:
            mock = _mock_vault_client(pub_raw)
            mock.secrets.transit.sign_data.return_value = {
                "data": {"signature": "garbage-no-colons"}
            }
            mock_cls.return_value = mock
            provider = VaultTransitKeyProvider(
                url="http://vault:8200", token="root", key_name="k"
            )
            with pytest.raises(KeyProviderError, match="malformed"):
                provider.sign(b"x")
