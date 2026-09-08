"""Native ETH invoice verification. Read-only RPC; no wallet keys or signing."""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class PaymentError(Exception):
    """Payment evidence is invalid; never grant an entitlement."""


class Pending(PaymentError):
    pass


class Unavailable(PaymentError):
    pass


class RetryLater(Unavailable):
    def __init__(self, seconds=60):
        self.seconds = max(1, int(seconds))
        super().__init__("Try again later")


def hexdata(value, size):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{%d}" % (size * 2), value):
        raise PaymentError("Invalid hexadecimal data")
    return value.lower()


def quantity(value):
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value):
        raise PaymentError("Invalid RPC quantity")
    return int(value, 16)


def rpc_hexdata(value, size):
    try:
        return hexdata(value, size)
    except PaymentError:
        raise Unavailable("Malformed RPC identity field") from None


def rpc_quantity(value):
    try:
        return quantity(value)
    except PaymentError:
        raise Unavailable("Malformed RPC quantity field") from None


class RPC:
    METHODS = {"eth_chainId", "eth_getTransactionByHash", "eth_getTransactionReceipt",
               "eth_getBlockByNumber", "eth_getCode"}

    def __init__(self, endpoint):
        parsed = urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("Configure a trusted HTTPS RPC endpoint")
        self.endpoint, self.hostname = endpoint, parsed.hostname
        self.retry_at = 0
        self.lock = threading.Lock()

    def __call__(self, method, params):
        if method not in self.METHODS:
            raise ValueError("Only read-only methods are allowed")
        with self.lock:
            if time.time() < self.retry_at:
                raise RetryLater(self.retry_at - time.time() + 1)
        request_id = secrets.token_hex(8)
        request = Request(self.endpoint, data=json.dumps({"jsonrpc": "2.0", "id": request_id,
                          "method": method, "params": params}).encode(),
                          headers={"Content-Type": "application/json", "User-Agent": "AgentContentStore/0.1"})
        try:
            with urlopen(request, timeout=10) as response:
                raw = response.read(1_000_001)
            if len(raw) > 1_000_000:
                raise Unavailable("Oversized RPC response")
            result = json.loads(raw)
        except HTTPError as exc:
            if exc.code == 429:
                delay = 900
                value = exc.headers.get("Retry-After", "")
                try:
                    delay = max(delay, int(value) if value.isdecimal() else
                                int(parsedate_to_datetime(value).timestamp() - time.time()) + 1)
                except (ValueError, TypeError, OverflowError):
                    pass
                with self.lock:
                    self.retry_at = time.time() + delay
                raise RetryLater(delay) from None
            raise Unavailable("RPC HTTP failure") from None
        except (URLError, OSError, ValueError, RecursionError):
            raise Unavailable("RPC unavailable") from None
        if not isinstance(result, dict) or result.get("jsonrpc") != "2.0" or result.get("id") != request_id:
            raise Unavailable("Invalid RPC response")
        if "error" in result or "result" not in result:
            raise Unavailable("RPC did not return a result")
        return result["result"]


@dataclass(frozen=True)
class Receipt:
    tx_hash: str
    block_hash: str
    block_number: int
    sender: str
    recipient: str
    amount_wei: int
    data: str


class DualRPCVerifier:
    def __init__(self, endpoints):
        if len(endpoints) != 2:
            raise ValueError("Two independently operated RPC endpoints are required")
        self.clients = [RPC(endpoint) for endpoint in endpoints]
        if self.clients[0].hostname == self.clients[1].hostname:
            raise ValueError("Use different RPC provider hosts")

    def ready(self, recipient):
        """Preflight on the deployment host before allowing invoice creation."""
        recipient = hexdata(recipient, 20)
        for rpc in self.clients:
            if rpc_quantity(rpc("eth_chainId", [])) != 1:
                raise Unavailable("RPC is not Ethereum mainnet")
            block = rpc("eth_getBlockByNumber", ["finalized", False])
            if not isinstance(block, dict):
                raise Unavailable("Finalized chain data unavailable")
            rpc_quantity(block.get("number"))
            rpc_hexdata(block.get("hash"), 32)
            if rpc("eth_getCode", [recipient, "latest"]) != "0x":
                raise Unavailable("This checkout requires a plain receiving account")
        return True

    @staticmethod
    def inspect(rpc, tx_hash, recipient, amount_wei, data):
        if rpc_quantity(rpc("eth_chainId", [])) != 1:
            raise PaymentError("Wrong chain")
        tx = rpc("eth_getTransactionByHash", [tx_hash])
        receipt = rpc("eth_getTransactionReceipt", [tx_hash])
        if tx is None or receipt is None:
            raise Pending("Transaction not yet confirmed")
        if not isinstance(tx, dict) or not isinstance(receipt, dict):
            raise Unavailable("Malformed transaction result")
        if rpc_quantity(receipt.get("status")) != 1:
            raise PaymentError("Transaction failed")
        if rpc_hexdata(tx.get("hash"), 32) != tx_hash or rpc_hexdata(receipt.get("transactionHash"), 32) != tx_hash:
            raise PaymentError("Wrong transaction")
        sender = rpc_hexdata(tx.get("from"), 20)
        if sender == recipient or rpc_hexdata(receipt.get("from"), 20) != sender:
            raise PaymentError("Invalid payer")
        if rpc_hexdata(tx.get("to"), 20) != recipient or rpc_hexdata(receipt.get("to"), 20) != recipient:
            raise PaymentError("Wrong recipient")
        if rpc_quantity(tx.get("value")) != amount_wei:
            raise PaymentError("Wrong native ETH amount")
        if not isinstance(tx.get("input"), str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", tx["input"]):
            raise Unavailable("Malformed RPC transaction input")
        if tx["input"].lower() != data:
            raise PaymentError("Transaction does not belong to this invoice")
        block_hash = rpc_hexdata(receipt.get("blockHash"), 32)
        block_number = rpc_quantity(receipt.get("blockNumber"))
        if rpc_hexdata(tx.get("blockHash"), 32) != block_hash or rpc_quantity(tx.get("blockNumber")) != block_number:
            raise PaymentError("Inconsistent transaction block")
        canonical = rpc("eth_getBlockByNumber", [hex(block_number), False])
        finalized = rpc("eth_getBlockByNumber", ["finalized", False])
        if not isinstance(canonical, dict) or not isinstance(finalized, dict):
            raise Unavailable("Block data unavailable")
        if rpc_hexdata(canonical.get("hash"), 32) != block_hash or rpc_quantity(canonical.get("number")) != block_number:
            raise PaymentError("Transaction is not on the canonical chain")
        rpc_hexdata(finalized.get("hash"), 32)
        if rpc_quantity(finalized.get("number")) < block_number:
            raise Pending("Waiting for Ethereum finalization")
        return Receipt(tx_hash, block_hash, block_number, sender, recipient, amount_wei, data)

    def verify(self, tx_hash, recipient, amount_wei, data):
        tx_hash, recipient = hexdata(tx_hash, 32), hexdata(recipient, 20)
        evidence = [self.inspect(rpc, tx_hash, recipient, amount_wei, data) for rpc in self.clients]
        if evidence[0] != evidence[1]:
            raise Unavailable("RPC providers disagree")
        return evidence[0]


class PaymentStore:
    def __init__(self, db_path, recipient, verifier, *, clock=time.time):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.recipient, self.verifier, self.clock = hexdata(recipient, 20), verifier, clock
        with closing(self.connect()) as db, db:
            db.executescript("""
              CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS orders (
                id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL,
                product TEXT NOT NULL, amount TEXT NOT NULL, asset_hash TEXT NOT NULL,
                created INTEGER NOT NULL, last_check INTEGER NOT NULL DEFAULT 0,
                paid INTEGER NOT NULL DEFAULT 0, tx_hash TEXT UNIQUE, evidence TEXT);
            """)
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT value FROM settings WHERE name='recipient'").fetchone()
            if row is not None and row[0] != self.recipient:
                raise ValueError("Existing database belongs to another receiving address")
            db.execute("INSERT OR IGNORE INTO settings VALUES ('recipient', ?)", (self.recipient,))
        os.chmod(self.path, 0o600)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    @staticmethod
    def token_hash(token):
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
            raise PaymentError("Invalid order credential")
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def data(order_id):
        return "0x" + b"buck-store-v1:".hex() + order_id

    def create_order(self, product_id, amount_wei, asset_sha256):
        if not re.fullmatch(r"[a-z0-9-]{1,80}", product_id):
            raise ValueError("Invalid product")
        if type(amount_wei) is not int or not 0 < amount_wei <= 10**18:
            raise ValueError("Invalid price")
        if not re.fullmatch(r"[0-9a-f]{64}", asset_sha256):
            raise ValueError("Invalid asset digest")
        order_id, token = secrets.token_hex(16), secrets.token_hex(32)
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            count = db.execute("SELECT count(*) FROM orders WHERE created >= ?", (int(self.clock()) - 86400,)).fetchone()[0]
            if count >= 1000:
                raise Unavailable("Daily order capacity reached")
            db.execute("INSERT INTO orders (id,token_hash,product,amount,asset_hash,created) VALUES (?,?,?,?,?,?)",
                       (order_id, self.token_hash(token), product_id, str(amount_wei), asset_sha256, int(self.clock())))
        result = self.get_order(order_id, token)
        result["bearer_token"] = token
        return result

    def lookup(self, db, order_id, token):
        digest = self.token_hash(token)
        if not isinstance(order_id, str) or not re.fullmatch(r"[0-9a-f]{32}", order_id):
            raise PaymentError("Invalid order credential")
        row = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
        if row is None or not hmac.compare_digest(row["token_hash"], digest):
            raise PaymentError("Invalid order credential")
        return row

    def get_order(self, order_id, token):
        with closing(self.connect()) as db:
            row = self.lookup(db, order_id, token)
        return {"order_id": row["id"], "product_id": row["product"],
                "status": "paid" if row["paid"] else "pending",
                "asset_sha256": row["asset_hash"], "amount_wei": row["amount"],
                "transaction": {"chainId": "0x1", "to": self.recipient,
                                "value": hex(int(row["amount"])), "data": self.data(row["id"])},
                "transaction_hash": row["tx_hash"], "confirmation_policy": "finalized_on_two_rpc_providers",
                "instructions": "Keep the bearer token. Send the exact transaction including data using your own authorized wallet; fees are additional. POST its transaction hash to the confirm URL. On 202 or 429, wait for Retry-After and repeat that POST until status is paid; GET status alone does not recheck the chain. Do not send tokens or use another network."}

    def confirm(self, order_id, token, tx_hash):
        tx_hash = hexdata(tx_hash, 32)
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = self.lookup(db, order_id, token)
            if row["paid"]:
                if row["tx_hash"] != tx_hash:
                    raise PaymentError("Order already has a different payment")
                return self.get_order(order_id, token)
            if row["last_check"] and self.clock() - row["last_check"] < 60:
                raise RetryLater(60 - (self.clock() - row["last_check"]))
            db.execute("UPDATE orders SET last_check=? WHERE id=?", (int(self.clock()), order_id))
        evidence = self.verifier.verify(tx_hash, self.recipient, int(row["amount"]), self.data(order_id))
        if not isinstance(evidence, Receipt) or (evidence.tx_hash, evidence.recipient, evidence.amount_wei, evidence.data) != (
                tx_hash, self.recipient, int(row["amount"]), self.data(order_id)):
            raise PaymentError("Invalid verifier result")
        try:
            with closing(self.connect()) as db, db:
                db.execute("BEGIN IMMEDIATE")
                current = self.lookup(db, order_id, token)
                if current["paid"] and current["tx_hash"] != tx_hash:
                    raise PaymentError("Order already paid")
                db.execute("UPDATE orders SET paid=1,tx_hash=?,evidence=? WHERE id=?",
                           (tx_hash, json.dumps(evidence.__dict__, sort_keys=True), order_id))
        except sqlite3.IntegrityError:
            raise PaymentError("Transaction already belongs to another order") from None
        return self.get_order(order_id, token)

    def entitlement(self, token):
        digest = self.token_hash(token)
        with closing(self.connect()) as db:
            row = db.execute("SELECT product,asset_hash FROM orders WHERE token_hash=? AND paid=1", (digest,)).fetchone()
        return dict(row) if row else None

    def authorized(self, product_id, token):
        try:
            entitlement = self.entitlement(token)
            return entitlement is not None and entitlement["product"] == product_id
        except PaymentError:
            return False
