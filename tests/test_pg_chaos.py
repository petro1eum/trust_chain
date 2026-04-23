"""Chaos / disaster-recovery integration tests.

Проверяем enterprise-инварианты ``PostgresVerifiableChainStore`` в условиях
сбоев:

1. **Pool kill mid-append** → append либо фиксируется полностью, либо
   откатывается (никаких «полу-записей» без Merkle leaf).
2. **Process crash + reopen** → после ``close()`` + ``reopen()`` длина и
   Merkle root восстанавливаются из ``chain_records`` (таблица — SOT).
3. **Manual DELETE из таблицы** → ``verify()`` детектирует
   несоответствие stored_root vs recomputed_root (tamper evidence).
4. **Concurrent appenders** → после конкурентных write-ов цепочка остаётся
   последовательной (seq монотонен, Merkle root пересчитывается корректно).
5. **Index rebuild** → после ``TRUNCATE`` in-memory Merkle кэша
   и ``rebuild_index()`` длина и корень совпадают с до-crash значениями.
"""

from __future__ import annotations

import threading

import pytest

from trustchain.v2.pg_verifiable_log import PostgresVerifiableChainStore

pytestmark = pytest.mark.integration


class TestPoolKillMidAppend:
    def test_aborted_transaction_does_not_corrupt_chain(
        self, postgres_chain_reset: str
    ) -> None:
        """Эмулируем смерть процесса во время append: закрываем pool перед
        commit-ом. Запись не должна «пролезть» в chain_records; следующий
        append стартует с правильной последовательности."""
        vlog = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            vlog.append("t", {"i": 0}, "sig0", "sid0")
            pre_len = vlog.length
            assert pre_len == 1

            # Пробуем append-нуть, но искусственно ломаем коммит.  Простейший
            # способ — закрыть pool прямо перед второй операцией: psycopg
            # поднимет ошибку, транзакция откатится.
            vlog.close()

            with pytest.raises(Exception):  # noqa: B017
                vlog.append("t", {"i": 1}, "sig1", "sid1")
        finally:
            pass

        reopened = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            assert (
                reopened.length == 1
            ), "аборт до commit НЕ должен был оставить записей"
            # Новый append идёт с seq=2 (SERIAL продолжает счёт, но leaf — №2)
            r = reopened.append("t", {"i": 2}, "sig2", "sid2")
            assert r["seq"] >= 2
            assert reopened.length == 2
        finally:
            reopened.close()


class TestProcessCrashRecovery:
    def test_length_and_root_recover_from_chain_records(
        self, postgres_chain_reset: str
    ) -> None:
        """После ``close()`` + новая инстанция: length и merkle_root берутся
        из таблицы ``chain_records`` (SOT), а не из кэша HEAD-строки."""
        vlog = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            for i in range(5):
                vlog.append("t", {"i": i}, f"s{i}", f"sid{i}")
            root_before = vlog.merkle_root
            length_before = vlog.length
        finally:
            vlog.close()

        recovered = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            assert recovered.length == length_before == 5
            assert recovered.merkle_root == root_before

            # И verify() подтверждает целостность.
            result = recovered.verify()
            assert result["valid"] is True
            assert result["length"] == 5
        finally:
            recovered.close()


class TestTamperEvidence:
    def test_manual_row_delete_is_detected(self, postgres_chain_reset: str) -> None:
        """Если supervillain-admin обходит append-only триггер и удаляет
        строку из chain_records, ``verify()`` возвращает valid=False
        (stored_root != recomputed).  Это и есть tamper-evidence контракт
        ADR-SEC-005: атака не останавливается на уровне БД, но обнаруживается
        при любой последующей верификации."""
        import psycopg

        from tests.conftest import _PG_STATE  # type: ignore

        admin_dsn = _PG_STATE.get("admin_dsn")
        if not admin_dsn:
            pytest.skip("admin DSN unavailable")

        vlog = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            for i in range(3):
                vlog.append("t", {"i": i}, f"s{i}", f"sid{i}")
            stored_root_before = vlog.merkle_root
            assert stored_root_before is not None
        finally:
            vlog.close()

        # Подделка из-под admin: отключаем триггер, удаляем строку, включаем.
        # В проде такое действие оставит CloudTrail/pg_audit-трейс — клиент
        # увидит несоответствие при первой же verify().
        with psycopg.connect(admin_dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute(
                "ALTER TABLE tc_verifiable_log.chain_records "
                "DISABLE TRIGGER chain_records_no_mutation"
            )
            try:
                cur.execute(
                    "DELETE FROM tc_verifiable_log.chain_records "
                    "WHERE seq = (SELECT MAX(seq) FROM tc_verifiable_log.chain_records)"
                )
            finally:
                cur.execute(
                    "ALTER TABLE tc_verifiable_log.chain_records "
                    "ENABLE TRIGGER chain_records_no_mutation"
                )

        tampered = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            result = tampered.verify()
            assert (
                result["valid"] is False
            ), "tamper ДОЛЖЕН детектироваться пересчётом Merkle root"
            assert result["stored_root"] != result["computed_root"]
        finally:
            tampered.close()

    def test_append_only_trigger_blocks_runtime_delete(
        self, postgres_chain_reset: str
    ) -> None:
        """Штатный клиент (роль ``tc_verifiable_log``) НЕ может удалить
        строку даже с ``SET session_replication_role``: прав нет.  Триггер —
        второй рубеж защиты поверх IAM."""
        import psycopg

        vlog = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            vlog.append("t", {"i": 0}, "s0", "sid0")
        finally:
            vlog.close()

        with psycopg.connect(postgres_chain_reset, autocommit=True) as conn:
            with conn.cursor() as cur:
                with pytest.raises(
                    (psycopg.errors.RaiseException, psycopg.Error),
                    match="append-only|permission denied",
                ):
                    cur.execute("DELETE FROM tc_verifiable_log.chain_records")


class TestConcurrentAppends:
    def test_seq_is_monotonic_under_contention(self, postgres_chain_reset: str) -> None:
        """N потоков append-ят одновременно. После всех: seq 1..N без
        пропусков, Merkle root можно пересчитать."""
        vlog = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        errors: list[BaseException] = []
        lock = threading.Lock()

        def worker(i: int) -> None:
            try:
                vlog.append("t", {"i": i}, f"sig{i}", f"sid{i}")
            except BaseException as e:
                with lock:
                    errors.append(e)

        try:
            threads = [threading.Thread(target=worker, args=(i,)) for i in range(25)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert not errors, f"errors during concurrent append: {errors}"

            assert vlog.length == 25
            # Seq 1..25 без дыр.
            rows = vlog.log(limit=100, reverse=False)
            seqs = sorted(r["seq"] for r in rows)
            assert seqs == list(range(1, 26))

            # И verify() зелёный.
            assert vlog.verify()["valid"] is True
        finally:
            vlog.close()


class TestIndexRebuild:
    def test_rebuild_index_reconstructs_merkle(self, postgres_chain_reset: str) -> None:
        """После ``rebuild_index()`` (перечитывание SOT из chain_records)
        in-memory Merkle tree совпадает с корнем до rebuild-а."""
        vlog = PostgresVerifiableChainStore(dsn=postgres_chain_reset)
        try:
            for i in range(10):
                vlog.append("t", {"i": i}, f"s{i}", f"sid{i}")
            root_before = vlog.merkle_root
            length_before = vlog.length

            res = vlog.rebuild_index()
            assert res["rebuilt"] is True
            assert res["records"] == length_before
            assert vlog.merkle_root == root_before
            assert vlog.length == length_before
        finally:
            vlog.close()
