"""Shared pytest fixtures for trust_chain v3 test suite.

``postgres_chain_dsn`` — session-scoped testcontainers Postgres 17 instance
with a dedicated role/schema for the verifiable chain log (ADR-SEC-002 layout).
Returns a DSN string; also exports it to ``TC_VERIFIABLE_LOG_DSN`` so tests
that construct ``TrustChainConfig(chain_storage='postgres')`` без явного DSN
тоже работают.

Если Docker недоступен — фикстура делает ``pytest.skip``, чтобы не ломать
``pytest -m 'not integration'`` на лаптопах без Docker.
"""

from __future__ import annotations

import os
import socket
from typing import Iterator

import pytest


def _docker_available() -> bool:
    if os.path.exists("/var/run/docker.sock"):
        return True
    host = os.environ.get("DOCKER_HOST", "")
    if host.startswith("tcp://"):
        try:
            hostport = host.removeprefix("tcp://")
            h, p = hostport.split(":", 1)
            with socket.create_connection((h, int(p)), timeout=0.5):
                return True
        except OSError:
            return False
    return False


@pytest.fixture(scope="session")
def postgres_chain_dsn() -> Iterator[str]:
    """PG 17 + role/schema ``tc_verifiable_log`` (ADR-SEC-002 parity)."""
    if not _docker_available():
        pytest.skip("Docker daemon is not available — PG integration tests skipped")

    try:
        from testcontainers.postgres import PostgresContainer  # type: ignore
    except ImportError:
        pytest.skip("testcontainers[postgresql] not installed")

    import psycopg

    container = PostgresContainer(
        image="postgres:17-alpine",
        username="trustchain_admin",
        password="admin_pw_test",
        dbname="trustchain",
    )
    container.start()
    try:
        host = container.get_container_host_ip()
        port = int(container.get_exposed_port(5432))

        admin_dsn = (
            f"postgresql://trustchain_admin:admin_pw_test@{host}:{port}/trustchain"
        )
        role, password, schema = "tc_verifiable_log", "vlog_pw_test", "tc_verifiable_log"

        with psycopg.connect(admin_dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
            cur.execute('REVOKE CREATE ON DATABASE "trustchain" FROM PUBLIC')
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,))
            if cur.fetchone() is None:
                cur.execute(f'CREATE ROLE "{role}" LOGIN PASSWORD %s', (password,))
            else:
                cur.execute(f'ALTER ROLE "{role}" WITH LOGIN PASSWORD %s', (password,))
            cur.execute("SELECT 1 FROM pg_namespace WHERE nspname = %s", (schema,))
            if cur.fetchone() is None:
                cur.execute(f'CREATE SCHEMA "{schema}" AUTHORIZATION "{role}"')
            cur.execute(f'REVOKE ALL ON SCHEMA "{schema}" FROM PUBLIC')
            cur.execute(f'GRANT USAGE, CREATE ON SCHEMA "{schema}" TO "{role}"')
            cur.execute(
                f'ALTER ROLE "{role}" IN DATABASE "trustchain" SET search_path TO "{schema}"'
            )

        dsn = f"postgresql://{role}:{password}@{host}:{port}/trustchain"
        os.environ["TC_VERIFIABLE_LOG_DSN"] = dsn
        yield dsn
        os.environ.pop("TC_VERIFIABLE_LOG_DSN", None)
    finally:
        container.stop()


@pytest.fixture
def postgres_chain_reset(postgres_chain_dsn: str) -> Iterator[str]:
    """Чистим chain_records / chain_head перед каждым тестом.

    ``chain_records`` защищена append-only-триггером, поэтому TRUNCATE через
    обычного пользователя заблокирован.  Временно отключаем сессионные
    триггеры через ``session_replication_role = 'replica'`` — это штатный
    PG-способ, которым пользуется pg_dump/logical replication.
    """
    import psycopg

    with psycopg.connect(postgres_chain_dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SET session_replication_role = 'replica'")
        try:
            cur.execute(
                "TRUNCATE TABLE chain_records, chain_head RESTART IDENTITY CASCADE"
            )
        except psycopg.errors.UndefinedTable:
            pass
        finally:
            cur.execute("SET session_replication_role = 'origin'")

    yield postgres_chain_dsn
