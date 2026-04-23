"""Shared pytest fixtures for trust_chain v3 test suite.

``postgres_chain_dsn`` — session-scoped testcontainers Postgres 17 instance
with a dedicated role/schema for the verifiable chain log (ADR-SEC-002 layout).
Returns a DSN string.

Важно: мы **не** экспортируем DSN в ``TC_VERIFIABLE_LOG_DSN`` на уровне
сессии, потому что тогда все тесты (включая юнит-тесты на in-memory backend)
ловят чужой postgres и падают с ``InsufficientPrivilege``.  Вместо этого
per-test autouse-фикстура ``_bind_pg_dsn_env`` проставляет DSN
только если конкретный тест явно запросил ``postgres_chain_dsn``
(или его производные).  Для юнит-тестов переменная всегда пуста.

Если Docker недоступен — фикстура делает ``pytest.skip``, чтобы не ломать
``pytest -m 'not integration'`` на лаптопах без Docker.
"""

from __future__ import annotations

import os
import socket
from typing import Iterator

import pytest

# Admin DSN для тестовых операций, требующих superuser (TRUNCATE на
# append-only-таблице с триггером, SET session_replication_role и пр.).
_PG_STATE: dict[str, str | None] = {"dsn": None, "admin_dsn": None}


@pytest.fixture(scope="session", autouse=True)
def _trustchain_tests_clear_stale_pg_dsn() -> Iterator[None]:
    """Случайный TC_VERIFIABLE_LOG_DSN из окружения разработчика ломает unit-тесты.

    Сохраняем исходное значение, чтобы вернуть его в конце сессии; но на время
    pytest-сессии переменная должна контролироваться исключительно фикстурой
    ``_bind_pg_dsn_env`` (см. ниже).

    Отключение: ``TRUSTCHAIN_PRESERVE_TC_VERIFIABLE_LOG_DSN=1``.
    """
    if os.environ.get("TRUSTCHAIN_PRESERVE_TC_VERIFIABLE_LOG_DSN", "").lower() in (
        "1",
        "true",
        "yes",
    ):
        yield
        return
    saved = os.environ.pop("TC_VERIFIABLE_LOG_DSN", None)
    try:
        yield
    finally:
        if saved is not None:
            os.environ["TC_VERIFIABLE_LOG_DSN"] = saved


@pytest.fixture(autouse=True)
def _bind_pg_dsn_env(request: pytest.FixtureRequest) -> Iterator[None]:
    """Per-test: выставляем TC_VERIFIABLE_LOG_DSN **только** тем тестам,
    которые реально запросили ``postgres_chain_dsn`` (или зависящую фикстуру).

    Без этого session-scoped DSN «протекал» бы во все последующие unit-тесты
    и ломал их InsufficientPrivilege / ownership-ошибками на чужой схеме.
    """
    wants_pg = any(
        name in request.fixturenames
        for name in ("postgres_chain_dsn", "postgres_chain_reset")
    )
    saved = os.environ.pop("TC_VERIFIABLE_LOG_DSN", None)
    try:
        if wants_pg and _PG_STATE["dsn"]:
            os.environ["TC_VERIFIABLE_LOG_DSN"] = _PG_STATE["dsn"]  # type: ignore[assignment]
        yield
    finally:
        os.environ.pop("TC_VERIFIABLE_LOG_DSN", None)
        if saved is not None:
            os.environ["TC_VERIFIABLE_LOG_DSN"] = saved


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
        role, password, schema = (
            "tc_verifiable_log",
            "vlog_pw_test",
            "tc_verifiable_log",
        )

        from psycopg import sql

        with psycopg.connect(admin_dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
            cur.execute('REVOKE CREATE ON DATABASE "trustchain" FROM PUBLIC')
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,))
            exists = cur.fetchone() is not None
            stmt = sql.SQL("{verb} ROLE {role} {with_} LOGIN PASSWORD {pw}").format(
                verb=sql.SQL("ALTER") if exists else sql.SQL("CREATE"),
                role=sql.Identifier(role),
                with_=sql.SQL("WITH") if exists else sql.SQL(""),
                pw=sql.Literal(password),
            )
            cur.execute(stmt)

            cur.execute("SELECT 1 FROM pg_namespace WHERE nspname = %s", (schema,))
            if cur.fetchone() is None:
                cur.execute(
                    sql.SQL("CREATE SCHEMA {schema} AUTHORIZATION {role}").format(
                        schema=sql.Identifier(schema), role=sql.Identifier(role)
                    )
                )
            cur.execute(
                sql.SQL("REVOKE ALL ON SCHEMA {schema} FROM PUBLIC").format(
                    schema=sql.Identifier(schema)
                )
            )
            cur.execute(
                sql.SQL("GRANT USAGE, CREATE ON SCHEMA {schema} TO {role}").format(
                    schema=sql.Identifier(schema), role=sql.Identifier(role)
                )
            )
            cur.execute(
                sql.SQL(
                    'ALTER ROLE {role} IN DATABASE "trustchain" '
                    "SET search_path TO {schema}"
                ).format(role=sql.Identifier(role), schema=sql.Identifier(schema))
            )

        dsn = f"postgresql://{role}:{password}@{host}:{port}/trustchain"
        _PG_STATE["dsn"] = dsn
        _PG_STATE["admin_dsn"] = admin_dsn
        yield dsn
    finally:
        _PG_STATE["dsn"] = None
        _PG_STATE["admin_dsn"] = None
        container.stop()


@pytest.fixture
def postgres_chain_reset(postgres_chain_dsn: str) -> Iterator[str]:
    """Чистим chain_records / chain_head перед каждым тестом.

    ``chain_records`` защищена append-only-триггером, а unprivileged-роль
    ``tc_verifiable_log`` не может ни ``SET session_replication_role``, ни
    ``ALTER TABLE ... DISABLE TRIGGER`` (в PG17 это требует SUPERUSER /
    owner-привилегий).  Поэтому сброс выполняем под **admin DSN** — это
    изолированный testcontainers, обычный production-flow не затрагивается.
    """
    import psycopg

    admin_dsn = _PG_STATE.get("admin_dsn")
    if not admin_dsn:
        pytest.skip("admin DSN unavailable (testcontainers fixture not initialized)")

    with psycopg.connect(admin_dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SET session_replication_role = 'replica'")
        try:
            cur.execute(
                "TRUNCATE TABLE "
                "tc_verifiable_log.chain_records, tc_verifiable_log.chain_head "
                "RESTART IDENTITY CASCADE"
            )
        except psycopg.errors.UndefinedTable:
            pass
        finally:
            cur.execute("SET session_replication_role = 'origin'")

    yield postgres_chain_dsn
