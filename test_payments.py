import copy
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("payments", Path(__file__).with_name("payments.py"))
p = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = p
spec.loader.exec_module(p)

RECIPIENT = "0x" + "11" * 20
SENDER = "0x" + "22" * 20
TX = "0x" + "33" * 32
BLOCK = "0x" + "44" * 32
ASSET = "55" * 32
AMOUNT = 100000000000000


class Node:
    def __init__(self, data="0x1234"):
        self.chain = "0x1"
        self.tx = {"hash": TX, "from": SENDER, "to": RECIPIENT, "value": hex(AMOUNT),
                   "input": data, "blockHash": BLOCK, "blockNumber": "0x64"}
        self.receipt = {"transactionHash": TX, "from": SENDER, "to": RECIPIENT,
                        "status": "0x1", "blockHash": BLOCK, "blockNumber": "0x64"}
        self.canonical = {"hash": BLOCK, "number": "0x64"}
        self.finalized = {"hash": "0x" + "66" * 32, "number": "0x80"}

    def __call__(self, method, params):
        if method == "eth_chainId": return self.chain
        if method == "eth_getCode": return "0x"
        if method == "eth_getTransactionByHash": return copy.deepcopy(self.tx)
        if method == "eth_getTransactionReceipt": return copy.deepcopy(self.receipt)
        if method == "eth_getBlockByNumber":
            return copy.deepcopy(self.finalized if params[0] == "finalized" else self.canonical)
        raise AssertionError("Unexpected RPC method")


def verifier(*nodes):
    instance = p.DualRPCVerifier(["https://provider-one.example", "https://provider-two.example"])
    instance.clients = list(nodes)
    return instance


class VerificationTests(unittest.TestCase):
    def test_success_requires_exact_native_transfer_and_finalized_block(self):
        result = verifier(Node(), Node()).verify(TX, RECIPIENT, AMOUNT, "0x1234")
        self.assertEqual(result, p.Receipt(TX, BLOCK, 100, SENDER, RECIPIENT, AMOUNT, "0x1234"))

    def test_wrong_network_amount_recipient_sender_invoice_and_failure_rejected(self):
        changes = [("chain", None, "0x2105"), ("tx", "value", hex(AMOUNT - 1)),
                   ("tx", "to", SENDER), ("receipt", "to", SENDER),
                   ("tx", "from", RECIPIENT), ("tx", "input", "0xabcd"),
                   ("receipt", "status", "0x0"), ("tx", "hash", BLOCK),
                   ("receipt", "transactionHash", BLOCK), ("receipt", "from", RECIPIENT)]
        for attr, key, value in changes:
            with self.subTest(attr=attr, key=key):
                node = Node()
                if key is None: setattr(node, attr, value)
                else: getattr(node, attr)[key] = value
                with self.assertRaises(p.PaymentError):
                    verifier(Node(), node).verify(TX, RECIPIENT, AMOUNT, "0x1234")

    def test_pending_missing_receipt_and_unfinalized_never_paid(self):
        for change in ("missing", "unfinalized"):
            node = Node()
            if change == "missing": node.receipt = None
            else: node.finalized["number"] = "0x63"
            with self.assertRaises(p.Pending):
                verifier(Node(), node).verify(TX, RECIPIENT, AMOUNT, "0x1234")

    def test_reorg_and_two_provider_disagreement_rejected(self):
        node = Node()
        node.canonical["hash"] = "0x" + "77" * 32
        with self.assertRaises(p.PaymentError):
            verifier(Node(), node).verify(TX, RECIPIENT, AMOUNT, "0x1234")
        node.tx["blockHash"] = node.receipt["blockHash"] = node.canonical["hash"]
        with self.assertRaises(p.Unavailable):
            verifier(Node(), node).verify(TX, RECIPIENT, AMOUNT, "0x1234")

    def test_rpc_outage_does_not_degrade_to_one_provider(self):
        def offline(*args): raise p.Unavailable("Offline")
        with self.assertRaises(p.Unavailable):
            verifier(Node(), offline).verify(TX, RECIPIENT, AMOUNT, "0x1234")

    def test_malformed_provider_fields_are_unavailable_not_buyer_errors(self):
        for field in ("blockHash", "blockNumber", "from", "to", "status", "transactionHash"):
            node = Node()
            node.receipt.pop(field)
            with self.subTest(field=field), self.assertRaises(p.Unavailable):
                verifier(Node(), node).verify(TX, RECIPIENT, AMOUNT, "0x1234")
        for value in (None, 123, "0x1", "invalid"):
            node = Node()
            node.tx["input"] = value
            with self.subTest(value=value), self.assertRaises(p.Unavailable):
                verifier(Node(), node).verify(TX, RECIPIENT, AMOUNT, "0x1234")

    def test_deeply_nested_provider_json_fails_as_unavailable(self):
        raw = b'[' * 2000 + b'0' + b']' * 2000
        with patch.object(p, "urlopen", return_value=io.BytesIO(raw)):
            with self.assertRaises(p.Unavailable):
                p.RPC("https://provider.example")("eth_chainId", [])

    def test_no_network_method_can_spend_or_sign(self):
        rpc = p.RPC("https://provider.example")
        for method in ("eth_sendRawTransaction", "eth_sendTransaction", "personal_sign"):
            with self.assertRaises(ValueError): rpc(method, [])


class OrderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = 1000
        self.nodes = [Node(), Node()]
        self.path = Path(self.tmp.name) / "orders.sqlite3"
        self.store = p.PaymentStore(self.path, RECIPIENT, verifier(*self.nodes), clock=lambda: self.now)
        self.order = self.store.create_order("test-pack", AMOUNT, ASSET)
        self.token, self.order_id = self.order["bearer_token"], self.order["order_id"]
        for node in self.nodes: node.tx["input"] = self.order["transaction"]["data"]

    def confirm(self, tx_hash=TX):
        return self.store.confirm(self.order_id, self.token, tx_hash)

    def test_unpaid_token_denied_then_paid_content_and_digest_bound(self):
        self.assertFalse(self.store.authorized("test-pack", self.token))
        self.assertEqual(self.confirm()["status"], "paid")
        self.assertTrue(self.store.authorized("test-pack", self.token))
        self.assertFalse(self.store.authorized("other-pack", self.token))
        self.assertEqual(self.store.entitlement(self.token), {"product": "test-pack", "asset_hash": ASSET})
        self.assertEqual(self.confirm()["transaction_hash"], TX)

    def test_public_transaction_hash_and_invoice_id_cannot_steal_order(self):
        with self.assertRaises(p.PaymentError):
            self.store.confirm(self.order_id, "99" * 32, TX)
        other = self.store.create_order("test-pack", AMOUNT, ASSET)
        with self.assertRaises(p.PaymentError):
            self.store.confirm(other["order_id"], other["bearer_token"], TX)
        self.assertFalse(self.store.authorized("test-pack", other["bearer_token"]))
        self.assertEqual(self.confirm()["status"], "paid")

    def test_failed_pending_and_unavailable_checks_do_not_unlock(self):
        for outcome in (p.PaymentError, p.Pending, p.Unavailable):
            with self.subTest(outcome=outcome):
                def fail(*args): raise outcome("No payment proof")
                self.store.verifier.verify = fail
                with self.assertRaises(outcome): self.confirm()
                self.assertFalse(self.store.authorized("test-pack", self.token))
                self.now += 61

    def test_poll_rate_limit_and_database_persistence(self):
        self.nodes[1].receipt = None
        with self.assertRaises(p.Pending): self.confirm()
        with self.assertRaises(p.RetryLater): self.confirm()
        self.nodes[1].receipt = copy.deepcopy(self.nodes[0].receipt)
        self.now += 60
        self.confirm()
        reopened = p.PaymentStore(self.path, RECIPIENT, verifier(*self.nodes))
        self.assertTrue(reopened.authorized("test-pack", self.token))

    def test_tokens_are_not_stored_in_plaintext_or_status_response(self):
        with self.store.connect() as db:
            row = dict(db.execute("SELECT * FROM orders").fetchone())
        self.assertNotIn(self.token, json.dumps(row))
        self.assertNotIn("bearer_token", self.store.get_order(self.order_id, self.token))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_existing_database_cannot_change_payment_address(self):
        with self.assertRaises(ValueError): p.PaymentStore(self.path, SENDER, verifier(*self.nodes))

    def test_concurrent_initializers_cannot_accept_different_recipients(self):
        path = Path(self.tmp.name) / "concurrent.sqlite3"
        barrier = threading.Barrier(2)
        def initialize(address):
            barrier.wait(timeout=5)
            try:
                return p.PaymentStore(path, address, verifier(*self.nodes))
            except ValueError:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(initialize, address) for address in (RECIPIENT, SENDER)]
            accepted = [result for future in futures if (result := future.result()) is not None]
        self.assertEqual(len(accepted), 1)
        with accepted[0].connect() as db:
            saved = db.execute("SELECT value FROM settings WHERE name='recipient'").fetchone()[0]
        self.assertEqual(accepted[0].recipient, saved)

    def test_transaction_unique_even_if_verifier_is_misconfigured(self):
        self.confirm()
        other = self.store.create_order("other-pack", AMOUNT, ASSET)
        self.store.verifier.verify = lambda tx, recipient, amount, data: p.Receipt(tx, BLOCK, 100, SENDER, recipient, amount, data)
        with self.assertRaises(p.PaymentError):
            self.store.confirm(other["order_id"], other["bearer_token"], TX)
        self.assertFalse(self.store.authorized("other-pack", other["bearer_token"]))


if __name__ == "__main__":
    unittest.main()
