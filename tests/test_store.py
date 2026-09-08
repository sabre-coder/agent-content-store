"""Real HTTP and SQLite integration, synthetic ZIPs, fake read-only RPC evidence only."""
import hashlib
import http.client
import io
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
import zipfile

from payments import PaymentError, PaymentStore, Pending, Receipt, RetryLater, Unavailable
from store import (MAX_BODY_BYTES, PRODUCT_ID, PRODUCT_PATH, PrivateFileStore, SOURCE_ROOT,
                   StoreApplication, load_catalog, make_server)

RECIPIENT = "0x" + "11" * 20
SENDER = "0x" + "22" * 20
TX = "0x" + "33" * 32
BLOCK = "0x" + "44" * 32
PAID_ID = "synthetic-demo-v1"
PAID_PATH = "/api/v1/products/" + PAID_ID
PREFIX = "/agent-content"
PRICE = 100000000000000


class FakeReadOnlyVerifier:
    def __init__(self):
        self.failure = None
        self.ready_result = True
        self.ready_calls = []
        self.verify_calls = []

    def ready(self, recipient):
        self.ready_calls.append(recipient)
        if isinstance(self.ready_result, Exception):
            raise self.ready_result
        return self.ready_result

    def verify(self, tx_hash, recipient, amount_wei, data):
        self.verify_calls.append((tx_hash, recipient, amount_wei, data))
        if self.failure is not None:
            raise self.failure
        return Receipt(tx_hash, BLOCK, 100, SENDER, recipient, amount_wei, data)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.private = self.directory / "private"
        self.private.mkdir()
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
            handle.writestr("test-only.json", '{"test_only":"PRIVATE-FIXTURE-CANARY","cases":[]}')
        self.synthetic = archive.getvalue()
        self.filename = PAID_ID + ".zip"
        (self.private / self.filename).write_bytes(self.synthetic)
        self.metadata = {"id": PAID_ID, "title": "Synthetic demo <fixture>",
                         "description": "A test-only downloadable dataset.", "price_wei": PRICE,
                         "asset_filename": self.filename,
                         "asset_sha256": hashlib.sha256(self.synthetic).hexdigest(),
                         "preview": {"fictional": True, "rows": [{"id": "public-example"}],
                                     "licence_text": "Synthetic test terms available before purchase."}}
        other = {**self.metadata, "id": "other-demo"}
        self.catalog_path = self.directory / "catalog.json"
        self.catalog_path.write_text(json.dumps({"products": [self.metadata, other]}))
        self.products = load_catalog(self.catalog_path)
        self.files = PrivateFileStore(self.private, {p.id: p.asset_filename for p in self.products if p.asset_filename})
        self.now = 1000
        self.verifier = FakeReadOnlyVerifier()
        self.db_path = self.directory / "orders.sqlite3"
        self.payments = PaymentStore(self.db_path, RECIPIENT, self.verifier, clock=lambda: self.now)
        self.server = self.thread = None
        self.restart()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=2)
            self.server = None

    def restart(self, *, enabled=True):
        self.stop_server()
        self.payments = PaymentStore(self.db_path, RECIPIENT, self.verifier, clock=lambda: self.now)
        self.application = StoreApplication(self.files, products=self.products, payment_store=self.payments,
                                            enable_checkout=enabled, prefix=PREFIX)
        self.server = make_server(port=0, application=self.application)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def request(self, path, method="GET", token=None, body=None, headers=None, *, port=None):
        connection = http.client.HTTPConnection("127.0.0.1", port or self.server.server_port, timeout=3)
        request_headers = dict(headers or {})
        if token is not None:
            request_headers["Authorization"] = "Bearer " + token
        if isinstance(body, dict):
            request_headers["Content-Type"] = "application/json"
            body = json.dumps(body)
        try:
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def follow(self, public_url, **kwargs):
        # Reproduce Kamal's documented inbound prefix stripping.
        self.assertTrue(public_url.startswith(PREFIX + "/"))
        return self.request(public_url[len(PREFIX):], **kwargs)

    def order(self):
        status, _, body = self.request(PAID_PATH + "/checkout", method="POST", body={})
        self.assertEqual(status, 201, body)
        return json.loads(body)

    def confirm(self, order, tx=TX):
        return self.follow(order["confirm_url"], method="POST", token=order["bearer_token"],
                           body={"transaction_hash": tx})

    def test_public_catalog_preview_licence_and_links_are_prefix_aware(self):
        status, _, body = self.request("/api/v1/catalog")
        self.assertEqual(status, 200)
        catalog = json.loads(body)
        self.assertTrue(catalog["checkout"]["available"])
        paid = next(p for p in catalog["products"] if p["id"] == PAID_ID)
        self.assertEqual(paid["price"]["amount_wei"], str(PRICE))
        self.assertEqual(paid["price"]["chain_id"], 1)
        for key in ("preview_url", "checkout_url", "download_url"):
            self.assertTrue(paid[key].startswith(PREFIX + "/api/v1/"))
        status, _, preview_body = self.follow(paid["preview_url"])
        self.assertEqual(status, 200)
        self.assertIn(b"Synthetic test terms available before purchase", preview_body)
        self.assertNotIn(b"PRIVATE-FIXTURE-CANARY", preview_body)
        status, _, landing = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn(b"Synthetic demo &lt;fixture&gt;", landing)
        self.assertIn((PREFIX + "/api/v1/catalog").encode(), landing)
        self.assertNotIn(b'href="/api/v1/', landing)
        self.assertNotIn(self.synthetic, landing)

    def test_builtin_fixtures_remain_free_preview_only(self):
        status, _, body = self.request(PRODUCT_PATH + "/preview")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["cases"]), 3)
        status, _, body = self.request(PRODUCT_PATH + "/checkout", method="POST", body={})
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body)["error"], "checkout_unavailable")

    def test_checkout_uses_only_fixed_server_price_digest_and_invoice_data(self):
        order = self.order()
        self.assertEqual(order["status"], "pending")
        self.assertEqual(order["amount_wei"], str(PRICE))
        self.assertEqual(order["asset_sha256"], self.metadata["asset_sha256"])
        self.assertEqual(order["transaction"]["chainId"], "0x1")
        self.assertEqual(order["transaction"]["to"], RECIPIENT)
        self.assertEqual(order["transaction"]["value"], hex(PRICE))
        self.assertEqual(order["transaction"]["data"], PaymentStore.data(order["order_id"]))
        self.assertEqual(len(order["bearer_token"]), 64)
        for override in ({"price_wei": 1}, {"status": "paid"}, {"asset_sha256": "0" * 64}, {"recipient": SENDER}):
            status, _, _ = self.request(PAID_PATH + "/checkout", method="POST", body=override)
            self.assertEqual(status, 400)
        with self.payments.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM orders").fetchone()[0], 1)

    def test_order_status_requires_matching_bearer_and_does_not_repeat_token(self):
        order = self.order()
        status, _, _ = self.follow(order["status_url"])
        self.assertEqual(status, 401)
        status, _, _ = self.follow(order["status_url"], token="9" * 64)
        self.assertEqual(status, 403)
        status, _, body = self.follow(order["status_url"], token=order["bearer_token"])
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "pending")
        self.assertNotIn(order["bearer_token"].encode(), body)

    def test_pending_confirmation_and_cooldown_do_not_grant_download(self):
        order = self.order()
        self.verifier.failure = Pending("Synthetic unfinalized receipt")
        status, headers, body = self.confirm(order)
        self.assertEqual(status, 202)
        self.assertEqual(json.loads(body)["status"], "pending")
        self.assertEqual(headers["Retry-After"], "60")
        self.assertEqual(json.loads(body)["confirm_url"], order["confirm_url"])
        self.assertIn("GET status does not recheck payment", json.loads(body)["message"])
        status, _, _ = self.follow(order["download_url"], token=order["bearer_token"])
        self.assertEqual(status, 403)
        status, headers, _ = self.confirm(order)
        self.assertEqual(status, 429)
        self.assertGreaterEqual(int(headers["Retry-After"]), 1)
        self.assertEqual(len(self.verifier.verify_calls), 1)
        self.verifier.failure = None
        self.now += 61
        status, _, body = self.follow(order["status_url"], token=order["bearer_token"])
        self.assertEqual(json.loads(body)["status"], "pending")
        self.assertEqual(len(self.verifier.verify_calls), 1)
        self.assertEqual(self.confirm(order)[0], 200)
        self.assertEqual(len(self.verifier.verify_calls), 2)

    def test_invalid_proof_and_rpc_outage_remain_unpaid(self):
        for failure, expected in ((PaymentError("Synthetic wrong invoice"), 422),
                                  (Unavailable("Synthetic outage"), 503),
                                  (RetryLater(900), 429)):
            with self.subTest(failure=type(failure).__name__):
                order = self.order()
                self.verifier.failure = failure
                status, headers, _ = self.confirm(order)
                self.assertEqual(status, expected)
                if expected == 429:
                    self.assertEqual(headers["Retry-After"], "900")
                status, _, body = self.follow(order["status_url"], token=order["bearer_token"])
                self.assertEqual(json.loads(body)["status"], "pending")
                status, _, _ = self.follow(order["download_url"], token=order["bearer_token"])
                self.assertEqual(status, 403)

    def test_paid_zip_download_survives_server_and_database_restart(self):
        order = self.order()
        self.assertEqual(self.confirm(order)[0], 200)
        self.restart()
        status, _, body = self.follow(order["status_url"], token=order["bearer_token"])
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "paid")
        status, headers, body = self.follow(order["download_url"], token=order["bearer_token"])
        self.assertEqual(status, 200)
        self.assertEqual(body, self.synthetic)
        self.assertEqual(headers["Content-Type"], "application/zip")
        self.assertEqual(headers["Content-Disposition"], 'attachment; filename="' + self.filename + '"')
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(self.verifier.verify_calls[0][2:], (PRICE, order["transaction"]["data"]))

    def test_entitlement_cannot_download_another_product_even_with_same_archive(self):
        order = self.order()
        self.assertEqual(self.confirm(order)[0], 200)
        status, _, body = self.request("/api/v1/products/other-demo/download", token=order["bearer_token"])
        self.assertEqual(status, 403)
        self.assertNotEqual(body, self.synthetic)

    def test_changed_asset_prevents_new_sales_and_invalidates_old_version_delivery(self):
        order = self.order()
        self.assertEqual(self.confirm(order)[0], 200)
        (self.private / self.filename).write_bytes(b"changed artifact")
        status, _, body = self.request(PAID_PATH + "/checkout", method="POST", body={})
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body)["error"], "artifact_unavailable")
        status, _, body = self.follow(order["download_url"], token=order["bearer_token"])
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(body)["error"], "artifact_version_mismatch")
        status, _, body = self.request("/api/v1/catalog")
        self.assertFalse(json.loads(body)["checkout"]["available"])

    def test_missing_artifact_prevents_sales(self):
        (self.private / self.filename).unlink()
        self.assertEqual(self.request(PAID_PATH + "/checkout", method="POST", body={})[0], 503)
        with self.payments.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM orders").fetchone()[0], 0)

    def test_private_files_cannot_be_reached_through_static_paths_or_query_tokens(self):
        order = self.order()
        self.assertEqual(self.confirm(order)[0], 200)
        for path in ("/" + self.filename, "/private/" + self.filename, "/assets/" + self.filename,
                     "/../" + self.filename, "/%2e%2e%2f" + self.filename, "/store.py", "/payments.py",
                     str(self.private / self.filename), PAID_PATH + "/download?token=" + order["bearer_token"]):
            with self.subTest(path=path):
                status, _, body = self.request(path)
                self.assertIn(status, (401, 404))
                self.assertNotEqual(body, self.synthetic)
        self.assertEqual(self.request(PAID_PATH + "/download", method="HEAD")[0], 401)

    def test_symlinked_asset_is_not_sold_or_delivered(self):
        order = self.order()
        self.assertEqual(self.confirm(order)[0], 200)
        path = self.private / self.filename
        path.unlink()
        other = self.directory / "other.zip"
        other.write_bytes(self.synthetic)
        path.symlink_to(other)
        self.assertEqual(self.request(PAID_PATH + "/checkout", method="POST", body={})[0], 503)
        self.assertEqual(self.follow(order["download_url"], token=order["bearer_token"])[0], 503)

    def test_preflight_must_pass_before_checkout_can_be_enabled(self):
        for readiness in (False, Unavailable("Synthetic preflight failure")):
            self.verifier.ready_result = readiness
            with self.assertRaises(Unavailable):
                StoreApplication(self.files, products=self.products, payment_store=self.payments, enable_checkout=True)
        self.verifier.ready_result = True
        (self.private / self.filename).write_bytes(b"wrong digest")
        with self.assertRaises(ValueError):
            StoreApplication(self.files, products=self.products, payment_store=self.payments, enable_checkout=True)
        self.assertEqual(len(self.verifier.ready_calls), 3)

    def test_disabled_checkout_preserves_existing_paid_downloads(self):
        order = self.order()
        self.assertEqual(self.confirm(order)[0], 200)
        self.restart(enabled=False)
        self.assertEqual(self.request(PAID_PATH + "/checkout", method="POST", body={})[0], 503)
        self.assertEqual(self.follow(order["download_url"], token=order["bearer_token"])[0], 200)

    def test_confirm_accepts_only_one_small_strict_transaction_hash_object(self):
        order = self.order()
        bad = [({"transaction_hash": TX, "paid": True}, 400), ({"tx_hash": TX}, 400),
               ({"transaction_hash": 3}, 400), ({"transaction_hash": "bad-hash"}, 422),
               ('{"transaction_hash":"' + TX + '","transaction_hash":"' + TX + '"}', 400),
               ('{"transaction_hash":NaN}', 400), ('[]', 400), ('x' * (MAX_BODY_BYTES + 1), 413)]
        for body, expected in bad:
            with self.subTest(body=str(body)[:40]):
                status, _, _ = self.follow(order["confirm_url"], method="POST", token=order["bearer_token"],
                                          body=body, headers={"Content-Type": "application/json"})
                self.assertEqual(status, expected)
        self.assertEqual(self.verifier.verify_calls, [])

    def test_catalog_rejects_invalid_price_duplicate_id_and_unsafe_filename(self):
        for changes in ({"price_wei": True}, {"price_wei": "100"}, {"price_wei": 0},
                        {"asset_filename": "../paid.zip"}, {"id": PRODUCT_ID}, {"asset_sha256": "wrong"}):
            with self.subTest(changes=changes):
                self.catalog_path.write_text(json.dumps({"products": [{**self.metadata, **changes}]}))
                with self.assertRaises(ValueError):
                    load_catalog(self.catalog_path)
        with self.assertRaises(ValueError):
            PrivateFileStore(SOURCE_ROOT, {PAID_ID: self.filename})

    def test_zero_prefix_produces_functional_direct_local_urls(self):
        application = StoreApplication(prefix="")
        self.assertEqual(application.catalog()["catalog_url"], "/api/v1/catalog")
        self.assertIn(b'href="/api/v1/catalog"', application.landing())
        self.assertFalse(application.catalog()["checkout"]["available"])

    def test_connection_limit_rejects_excess_clients_without_new_workers(self):
        limited = make_server(port=0, application=self.application, max_connections=1, request_timeout=2)
        thread = threading.Thread(target=limited.serve_forever, daemon=True)
        thread.start()
        first = socket.create_connection(("127.0.0.1", limited.server_port), timeout=2)
        try:
            first.sendall(b"GET /api/v1/catalog HTTP/1.1\r\nHost: localhost\r\n")
            status, headers, _ = self.request("/api/v1/catalog", port=limited.server_port)
            self.assertEqual(status, 503)
            self.assertEqual(headers["Retry-After"], "5")
        finally:
            first.close()
            limited.shutdown()
            limited.server_close()
            thread.join(timeout=2)

    def test_incomplete_request_body_times_out(self):
        limited = make_server(port=0, application=self.application, request_timeout=0.2)
        thread = threading.Thread(target=limited.serve_forever, daemon=True)
        thread.start()
        client = socket.create_connection(("127.0.0.1", limited.server_port), timeout=2)
        try:
            client.sendall(("POST " + PAID_PATH + "/checkout HTTP/1.1\r\nHost: localhost\r\n"
                            "Content-Type: application/json\r\nContent-Length: 20\r\n\r\n{").encode())
            self.assertIn(b"408", client.recv(512).split(b"\r\n", 1)[0])
        finally:
            client.close()
            limited.shutdown()
            limited.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
