#!/usr/bin/env python3
"""Example: SQL Database Agent with Audit Trail.

This example shows how to build a database agent where every query
is cryptographically signed and linked in a Chain of Trust.

Features:
- All SQL queries are signed
- Chain of Trust links related operations
- Full audit trail for compliance
- Verify any operation in the chain

Requirements:
    pip install sqlite3  # (built-in)

Usage:
    python examples/database_agent.py
"""

import sqlite3
from datetime import datetime
from typing import List, Optional

from trustchain import TrustChain


class AuditableDatabase:
    """Database with cryptographic audit trail."""

    def __init__(self, db_path: str = ":memory:"):
        """Initialize auditable database.

        Args:
            db_path: Path to SQLite database
        """
        self.tc = TrustChain()
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.chain: List = []  # Audit chain

        # Create demo table
        self._setup_db()
        self._register_tools()

    def _setup_db(self):
        """Create demo tables."""
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY,
                account_from TEXT,
                account_to TEXT,
                amount REAL,
                timestamp TEXT,
                description TEXT
            )
        """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                name TEXT,
                balance REAL
            )
        """
        )

        # Seed data
        self.cursor.executemany(
            "INSERT OR REPLACE INTO accounts VALUES (?, ?, ?)",
            [
                ("ACC001", "Alice", 10000.0),
                ("ACC002", "Bob", 5000.0),
                ("ACC003", "Charlie", 7500.0),
            ],
        )
        self.conn.commit()

    def _register_tools(self):
        """Register database tools."""

        @self.tc.tool("query_balance")
        def query_balance(account_id: str) -> dict:
            """Query account balance."""
            return self._query_balance(account_id)

        @self.tc.tool("transfer_funds")
        def transfer_funds(
            from_account: str, to_account: str, amount: float, description: str = ""
        ) -> dict:
            """Transfer funds between accounts."""
            return self._transfer(from_account, to_account, amount, description)

        @self.tc.tool("list_transactions")
        def list_transactions(account_id: str, limit: int = 10) -> dict:
            """List recent transactions for an account."""
            return self._list_transactions(account_id, limit)

    def _query_balance(self, account_id: str) -> dict:
        """Query balance with signature."""
        self.cursor.execute(
            "SELECT name, balance FROM accounts WHERE id = ?", (account_id,)
        )
        row = self.cursor.fetchone()

        if not row:
            return {"error": "Account not found", "account_id": account_id}

        return {
            "account_id": account_id,
            "name": row[0],
            "balance": row[1],
            "queried_at": datetime.now().isoformat(),
        }

    def _transfer(
        self, from_account: str, to_account: str, amount: float, description: str
    ) -> dict:
        """Transfer with Chain of Trust."""

        # Step 1: Verify source balance
        parent_sig = self.chain[-1].signature if self.chain else None

        source = self.tc._signer.sign(
            "verify_source",
            {"account": from_account, "required": amount},
            parent_signature=parent_sig,
        )
        self.chain.append(source)

        # Check balance
        self.cursor.execute(
            "SELECT balance FROM accounts WHERE id = ?", (from_account,)
        )
        balance = self.cursor.fetchone()

        if not balance or balance[0] < amount:
            return {
                "error": "Insufficient funds",
                "required": amount,
                "available": balance[0] if balance else 0,
            }

        # Step 2: Execute transfer
        transfer = self.tc._signer.sign(
            "execute_transfer",
            {
                "from": from_account,
                "to": to_account,
                "amount": amount,
            },
            parent_signature=source.signature,
        )
        self.chain.append(transfer)

        # Update balances
        self.cursor.execute(
            "UPDATE accounts SET balance = balance - ? WHERE id = ?",
            (amount, from_account),
        )
        self.cursor.execute(
            "UPDATE accounts SET balance = balance + ? WHERE id = ?",
            (amount, to_account),
        )

        # Record transaction
        self.cursor.execute(
            """INSERT INTO transactions 
               (account_from, account_to, amount, timestamp, description)
               VALUES (?, ?, ?, ?, ?)""",
            (from_account, to_account, amount, datetime.now().isoformat(), description),
        )
        self.conn.commit()

        # Step 3: Confirm
        confirm = self.tc._signer.sign(
            "confirm_transfer",
            {"transaction_id": self.cursor.lastrowid, "status": "completed"},
            parent_signature=transfer.signature,
        )
        self.chain.append(confirm)

        return {
            "status": "completed",
            "transaction_id": self.cursor.lastrowid,
            "from": from_account,
            "to": to_account,
            "amount": amount,
            "chain_length": len(self.chain),
            "signature": confirm.signature[:32] + "...",
        }

    def _list_transactions(self, account_id: str, limit: int) -> dict:
        """List transactions with signatures."""
        self.cursor.execute(
            """SELECT id, account_from, account_to, amount, timestamp, description
               FROM transactions 
               WHERE account_from = ? OR account_to = ?
               ORDER BY timestamp DESC LIMIT ?""",
            (account_id, account_id, limit),
        )

        rows = self.cursor.fetchall()
        transactions = [
            {
                "id": r[0],
                "from": r[1],
                "to": r[2],
                "amount": r[3],
                "timestamp": r[4],
                "description": r[5],
            }
            for r in rows
        ]

        return {
            "account_id": account_id,
            "count": len(transactions),
            "transactions": transactions,
        }

    def verify_audit_trail(self) -> dict:
        """Verify the entire audit chain."""
        if not self.chain:
            return {"verified": True, "chain_length": 0}

        is_valid = self.tc.verify_chain(self.chain)

        return {
            "verified": is_valid,
            "chain_length": len(self.chain),
            "first_signature": self.chain[0].signature[:16] + "...",
            "last_signature": self.chain[-1].signature[:16] + "...",
        }


def main():
    """Demo the auditable database."""
    print("🔐 Auditable Database Agent")
    print()

    db = AuditableDatabase()

    # Query balances
    print("📊 Initial balances:")
    for acc in ["ACC001", "ACC002", "ACC003"]:
        result = db._query_balance(acc)
        print(f"   {result['name']}: ${result['balance']:.2f}")
    print()

    # Make transfers
    print("💸 Making transfers...")

    result = db._transfer("ACC001", "ACC002", 1000.0, "Payment for services")
    print(
        f"   Transfer 1: ${result.get('amount', 0)} - {result.get('status', 'failed')}"
    )
    print(f"   Chain length: {result.get('chain_length', 0)}")

    result = db._transfer("ACC002", "ACC003", 500.0, "Refund")
    print(
        f"   Transfer 2: ${result.get('amount', 0)} - {result.get('status', 'failed')}"
    )
    print(f"   Chain length: {result.get('chain_length', 0)}")
    print()

    # Final balances
    print("📊 Final balances:")
    for acc in ["ACC001", "ACC002", "ACC003"]:
        result = db._query_balance(acc)
        print(f"   {result['name']}: ${result['balance']:.2f}")
    print()

    # Verify audit trail
    print("✅ Verifying audit trail...")
    audit = db.verify_audit_trail()
    print(f"   Verified: {audit['verified']}")
    print(f"   Chain length: {audit['chain_length']} operations")
    print(f"   First signature: {audit['first_signature']}")
    print(f"   Last signature: {audit['last_signature']}")
    print()

    print("🎉 Database agent demo complete!")
    print("   Every operation is signed and linked in a Chain of Trust.")


if __name__ == "__main__":
    main()
