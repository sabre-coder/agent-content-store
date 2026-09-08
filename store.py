#!/usr/bin/env python3
"""API-first content store with independently verified native Ethereum invoices."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import hmac
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import socket
import stat
import threading
import time
from typing import Mapping, Protocol
from urllib.parse import unquote, urlsplit

from payments import DualRPCVerifier, PaymentError, PaymentStore, Pending, RetryLater, Unavailable

SOURCE_ROOT = Path(__file__).resolve().parent
PRODUCT_ID = "json-import-regressions"
PRODUCT_PATH = "/api/v1/products/" + PRODUCT_ID
MAX_ASSET_BYTES = 2_000_000
MAX_BODY_BYTES = 2048
MAX_CATALOG_BYTES = 512_000

PREVIEW = {
    "schema_version": "1.0",
    "product_id": PRODUCT_ID,
    "artifact_status": "synthetic_free_preview",
    "description": "Boundary cases for a deliberately small JSON-record contract.",
    "contract": {
        "input": "An object with exactly id and count; no extra properties.",
        "id": "A string with at least one non-whitespace character; preserve its value.",
        "count": "A JSON integer from 0 to 100 inclusive; booleans are rejected.",
        "error_order": "Check object type, required fields, extra fields, id, then count.",
        "numeric_representation": "The lexical distinction between 1 and 1.0 is outside this preview.",
    },
    "cases": [
        {"id": "zero-is-valid", "input": {"id": "example", "count": 0},
         "expected": {"valid": True, "output": {"id": "example", "count": 0}}},
        {"id": "boolean-is-not-a-count", "input": {"id": "example", "count": True},
         "expected": {"valid": False, "error": {"code": "count_type", "path": ["count"]}}},
        {"id": "blank-identifier", "input": {"id": "  ", "count": 2},
         "expected": {"valid": False, "error": {"code": "id_blank", "path": ["id"]}}},
    ],
}


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("Duplicate JSON member")
            result[key] = value
        return result

    def constant(value):
        raise ValueError("Non-finite JSON number")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


@dataclass(frozen=True)
class Product:
    id: str
    title: str
    description: str
    preview: dict
    price_wei: int | None = None
    asset_filename: str | None = None
    asset_sha256: str | None = None


FREE_PRODUCT = Product(PRODUCT_ID, "JSON import regression fixtures",
                       "Three free synthetic input/output cases for importer tests.", PREVIEW)


def load_catalog(path: Path | None) -> list[Product]:
    products = [FREE_PRODUCT]
    if path is None:
        return products
    with path.open("rb") as handle:
        raw = handle.read(MAX_CATALOG_BYTES + 1)
    if len(raw) > MAX_CATALOG_BYTES:
        raise ValueError("Catalog exceeds the size limit")
    document = strict_json(raw.decode("utf-8"))
    rows = document.get("products") if isinstance(document, dict) else document
    if not isinstance(rows, list) or len(rows) > 20:
        raise ValueError("Catalog must contain at most 20 paid product records")
    seen = {PRODUCT_ID}
    required = {"id", "title", "description", "price_wei", "asset_filename", "asset_sha256", "preview"}
    for row in rows:
        if not isinstance(row, dict) or set(row) != required:
            raise ValueError("Each product must contain exactly the documented catalog fields")
        if not isinstance(row["id"], str) or not re.fullmatch(r"[a-z0-9-]{1,80}", row["id"]) or row["id"] in seen:
            raise ValueError("Invalid or duplicate product ID")
        if not isinstance(row["title"], str) or not 1 <= len(row["title"]) <= 200:
            raise ValueError("Invalid product title")
        if not isinstance(row["description"], str) or not 1 <= len(row["description"]) <= 2000:
            raise ValueError("Invalid product description")
        if type(row["price_wei"]) is not int or not 0 < row["price_wei"] <= 10**18:
            raise ValueError("Price must be a positive integer number of wei, at most one ETH")
        if not isinstance(row["asset_filename"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", row["asset_filename"]):
            raise ValueError("Asset mappings must use plain filenames")
        if not isinstance(row["asset_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["asset_sha256"]):
            raise ValueError("Invalid asset SHA-256")
        if not isinstance(row["preview"], dict):
            raise ValueError("Preview must be a public JSON object")
        products.append(Product(**row))
        seen.add(row["id"])
    return products


@dataclass(frozen=True)
class Entitlement:
    """Trusted backend result, never accepted from caller JSON."""
    product_id: str
    asset_sha256: str
    expires_at: float


class EntitlementResolver(Protocol):
    def resolve(self, bearer_token: str) -> Entitlement | None:
        ...


class DenyAllEntitlements:
    def resolve(self, bearer_token: str) -> None:
        return None


class PaymentEntitlements:
    def __init__(self, payments: PaymentStore):
        self.payments = payments

    def resolve(self, bearer_token: str) -> Entitlement | None:
        result = self.payments.entitlement(bearer_token)
        if result is None:
            return None
        return Entitlement(result["product"], result["asset_hash"], float("inf"))


class PrivateFileStore:
    """Only application-owned product mappings select files, never URL paths."""
    def __init__(self, directory: Path, assets: Mapping[str, str]):
        self.directory = directory.resolve(strict=True)
        if not self.directory.is_dir():
            raise ValueError("Private storage must be an existing directory")
        if self.directory == SOURCE_ROOT or SOURCE_ROOT in self.directory.parents:
            raise ValueError("Keep private assets outside the public source directory")
        self.assets = dict(assets)
        for name in self.assets.values():
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", name):
                raise ValueError("Asset mappings must use plain filenames")

    def read(self, product_id: str) -> bytes:
        name = self.assets.get(product_id)
        if name is None:
            raise FileNotFoundError("No private artifact is installed")
        path = self.directory / name
        if path.is_symlink():
            raise ValueError("Private asset symlinks are not supported")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ASSET_BYTES:
                raise ValueError("Invalid private artifact")
            content = handle.read(MAX_ASSET_BYTES + 1)
        if len(content) > MAX_ASSET_BYTES:
            raise ValueError("Private artifact exceeds the size limit")
        return content


class RequestError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


def bearer_token(authorization):
    if not isinstance(authorization, str):
        raise RequestError(401, "entitlement_required")
    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not re.fullmatch(r"[0-9a-f]{64}", token):
        raise RequestError(401, "invalid_entitlement")
    return token


class StoreApplication:
    def __init__(self, private_files: PrivateFileStore | None = None,
                 entitlements: EntitlementResolver | None = None, *, products=None,
                 payment_store: PaymentStore | None = None, enable_checkout=False,
                 prefix=""):
        if prefix == "/":
            prefix = ""
        prefix = prefix.rstrip("/")
        if prefix and not re.fullmatch(r"(?:/[A-Za-z0-9_-]+)+", prefix):
            raise ValueError("Prefix must be an absolute path without query strings or traversal")
        self.prefix = prefix
        self.private_files = private_files
        self.products = {product.id: product for product in (products or [FREE_PRODUCT])}
        self.payments = payment_store
        self.entitlements = entitlements if entitlements is not None else (
            PaymentEntitlements(payment_store) if payment_store is not None else DenyAllEntitlements())
        self.checkout_enabled = False
        if enable_checkout:
            if payment_store is None:
                raise ValueError("Checkout requires an invoice database and payment verifier")
            if not any(product.price_wei is not None and self.installed(product) for product in self.products.values()):
                raise ValueError("Checkout requires an installed artifact matching its catalog SHA-256")
            if payment_store.verifier.ready(payment_store.recipient) is not True:
                raise Unavailable("Payment verifier is not ready")
            self.checkout_enabled = True

    def url(self, path):
        return self.prefix + path

    def installed(self, product):
        if self.private_files is None or product.asset_sha256 is None:
            return False
        try:
            data = self.private_files.read(product.id)
            return hmac.compare_digest(hashlib.sha256(data).hexdigest(), product.asset_sha256)
        except (OSError, ValueError):
            return False

    def catalog(self):
        rows = []
        for product in self.products.values():
            installed = self.installed(product)
            purchasable = product.price_wei is not None and installed and self.checkout_enabled
            base = "/api/v1/products/" + product.id
            rows.append({"id": product.id, "title": product.title, "description": product.description,
                         "availability": "available" if purchasable else (
                             "preview_only" if product.price_wei is None else "checkout_unavailable"),
                         "artifact_installed": installed, "checkout_available": purchasable,
                         "price": None if product.price_wei is None else {
                             "network": "ethereum-mainnet", "chain_id": 1, "currency": "ETH",
                             "amount_wei": str(product.price_wei), "network_fees_included": False},
                         "asset_sha256": product.asset_sha256,
                         "preview_url": self.url(base + "/preview"),
                         "checkout_url": self.url(base + "/checkout"),
                         "download_url": self.url(base + "/download")})
        return {"schema_version": "1.0", "catalog_url": self.url("/api/v1/catalog"),
                "documentation_url": "https://github.com/sabre-coder/agent-content-store#api-flow",
                "checkout": {"available": any(row["checkout_available"] for row in rows),
                             "confirmation_policy": "finalized_on_two_rpc_providers"}, "products": rows}

    def public_preview(self, product):
        return {**product.preview, "product_id": product.id,
                "catalog_url": self.url("/api/v1/catalog"),
                "checkout_url": self.url("/api/v1/products/" + product.id + "/checkout")}

    def order_urls(self, order):
        base = "/api/v1/orders/" + order["order_id"]
        return {**order, "status_url": self.url(base), "confirm_url": self.url(base + "/confirm"),
                "download_url": self.url("/api/v1/products/" + order["product_id"] + "/download")}

    def create_order(self, product):
        if not self.checkout_enabled or self.payments is None or product.price_wei is None:
            raise RequestError(503, "checkout_unavailable")
        # Recheck immediately before issuing each invoice, not just at startup.
        if not self.installed(product):
            raise RequestError(503, "artifact_unavailable")
        return self.order_urls(self.payments.create_order(product.id, product.price_wei, product.asset_sha256))

    def get_order(self, order_id, token):
        if self.payments is None:
            raise RequestError(503, "checkout_unavailable")
        try:
            return self.order_urls(self.payments.get_order(order_id, token))
        except PaymentError:
            raise RequestError(403, "invalid_order_credential") from None

    def download(self, product_id, authorization):
        product = self.products.get(product_id)
        if product is None:
            return 404, {"error": "not_found"}
        try:
            token = bearer_token(authorization)
            entitlement = self.entitlements.resolve(token)
            if (not isinstance(entitlement, Entitlement) or entitlement.product_id != product_id
                    or not entitlement.expires_at > time.time()
                    or not isinstance(entitlement.asset_sha256, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", entitlement.asset_sha256)):
                return 403, {"error": "invalid_entitlement"}
            if self.private_files is None:
                return 503, {"error": "artifact_unavailable"}
            content = self.private_files.read(product_id)
            # Bind to the purchased version even after a server restart/catalog update.
            if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), entitlement.asset_sha256):
                return 503, {"error": "artifact_version_mismatch"}
            return 200, content
        except RequestError as error:
            return error.status, {"error": error.code}
        except PaymentError:
            return 403, {"error": "invalid_entitlement"}
        except Exception:
            return 503, {"error": "delivery_unavailable"}

    def landing(self):
        catalog = self.catalog()
        cards = []
        for product in catalog["products"]:
            price = product["price"]
            if price is None:
                status = "Free preview"
            elif product["checkout_available"]:
                wei = int(price["amount_wei"])
                amount = f"{wei // 10**18}.{wei % 10**18:018d}".rstrip("0").rstrip(".")
                status = amount + " native ETH on Ethereum mainnet; network fees extra"
            else:
                status = "Preview available; checkout unavailable"
            cards.append('<article><h2>' + escape(product["title"]) + '</h2><p>' +
                         escape(product["description"]) + '</p><p class="price">' + escape(status) +
                         '</p><p><a href="' + escape(product["preview_url"], quote=True) +
                         '">Read the free JSON preview</a></p></article>')
        notice = ("Checkout creates an invoice for your own authorized wallet. Keep its bearer token. "
                  "Delivery unlocks after the exact native ETH payment is finalized and verified by two providers."
                  if catalog["checkout"]["available"] else "Checkout is unavailable. Do not send payment.")
        catalog_url = escape(self.url("/api/v1/catalog"), quote=True)
        return ('''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Agent Content Store</title>
<style>body{max-width:48rem;margin:4rem auto;padding:0 1.25rem;font:18px/1.6 system-ui,sans-serif;color:#17232b;background:#fafaf6}h1{line-height:1.15}a{color:#075d70}article{margin:2rem 0;padding:1.25rem;border:1px solid #cfd7ce;border-radius:.7rem}code{font-size:.85em;overflow-wrap:anywhere}.price{font-weight:600}.status{padding:1rem;background:#fff0cc;border-radius:.5rem}</style>
<main><p>Agent Content Store</p><h1>Useful data, ready for your next build.</h1>
<p>Inspect a free preview, create an invoice through the API, and download the purchased artifact.
People and software use the same endpoints.</p>''' + ''.join(cards) +
                '<p class="status">' + escape(notice) + '</p><h2>For API clients</h2><p><a href="' +
                catalog_url + '"><code>GET ' + catalog_url + '</code></a> lists products, prices, and endpoint URLs.</p>'
                '<p><a href="https://github.com/sabre-coder/agent-content-store#api-flow">Read the complete purchase API instructions</a>.</p>'
                '<p>POST an empty JSON object to a product’s checkout URL. Save the returned bearer token and transaction request. '
                'Use that token in the Authorization header when checking the order, confirming payment, and downloading. '
                'The store never requests wallet keys or signs transactions.</p></main></html>').encode("utf-8")


class LimitedHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, handler, *, max_connections=8, request_timeout=10):
        self.slots = threading.BoundedSemaphore(max_connections)
        self.request_timeout = request_timeout
        super().__init__(address, handler)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(self.request_timeout)
        return request, address

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nRetry-After: 5\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # Never print headers, request bodies, tokens, or backend exception details.
        pass


def handler_for(application):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AgentContentStore/0.2"
        sys_version = ""

        def log_message(self, format, *args):
            pass

        def respond(self, status, payload, *, content_type="application/json; charset=utf-8", filename=None, retry_after=None):
            body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8") if isinstance(payload, dict) else payload
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Connection", "close")
            if status == 401:
                self.send_header("WWW-Authenticate", 'Bearer realm="content"')
            if filename is not None:
                self.send_header("Content-Disposition", 'attachment; filename="' + filename + '"')
            if retry_after is not None:
                self.send_header("Retry-After", str(max(1, int(retry_after))))
            self.end_headers()
            self.close_connection = True
            if self.command != "HEAD":
                self.wfile.write(body)

        def authorization(self):
            values = self.headers.get_all("Authorization", [])
            if len(values) != 1:
                raise RequestError(401, "entitlement_required")
            return values[0]

        def json_body(self, *, optional=False):
            if self.headers.get_all("Transfer-Encoding"):
                raise RequestError(400, "unsupported_transfer_encoding")
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) > 1 or (lengths and not re.fullmatch(r"[0-9]{1,10}", lengths[0])):
                raise RequestError(400, "invalid_content_length")
            size = int(lengths[0]) if lengths else 0
            if size > MAX_BODY_BYTES:
                raise RequestError(413, "request_too_large")
            if size == 0:
                if optional:
                    return {}
                raise RequestError(400, "json_object_required")
            if self.headers.get_content_type() != "application/json":
                raise RequestError(415, "application_json_required")
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise RequestError(400, "incomplete_request")
            try:
                value = strict_json(raw.decode("utf-8"))
            except (ValueError, UnicodeError, RecursionError):
                raise RequestError(400, "invalid_json") from None
            if not isinstance(value, dict):
                raise RequestError(400, "json_object_required")
            return value

        def dispatch(self):
            if len(self.path) > 2048:
                raise RequestError(414, "request_target_too_long")
            path = unquote(urlsplit(self.path).path)
            if self.command in {"GET", "HEAD"}:
                if path == "/":
                    return self.respond(200, application.landing(), content_type="text/html; charset=utf-8")
                if path == "/api/v1/catalog":
                    return self.respond(200, application.catalog())
            product_match = re.fullmatch(r"/api/v1/products/([a-z0-9-]{1,80})/(preview|checkout|download)", path)
            if product_match:
                product = application.products.get(product_match[1])
                if product is None:
                    raise RequestError(404, "not_found")
                action = product_match[2]
                if self.command in {"GET", "HEAD"} and action == "preview":
                    return self.respond(200, application.public_preview(product))
                if self.command in {"GET", "HEAD"} and action == "download":
                    status, payload = application.download(product.id, self.authorization())
                    filename = product.asset_filename if status == 200 else None
                    mime = "application/json; charset=utf-8"
                    if filename is not None:
                        mime = "application/zip" if filename.lower().endswith(".zip") else (
                            "application/json; charset=utf-8" if filename.lower().endswith(".json") else "application/octet-stream")
                    return self.respond(status, payload, content_type=mime, filename=filename)
                if self.command == "POST" and action == "checkout":
                    if self.json_body(optional=True):
                        raise RequestError(400, "checkout_accepts_no_overrides")
                    return self.respond(201, application.create_order(product))
            order_match = re.fullmatch(r"/api/v1/orders/([0-9a-f]{32})(/confirm)?", path)
            if order_match:
                token = bearer_token(self.authorization())
                order = application.get_order(order_match[1], token)
                if self.command in {"GET", "HEAD"} and order_match[2] is None:
                    return self.respond(200, order)
                if self.command == "POST" and order_match[2] == "/confirm":
                    body = self.json_body()
                    if set(body) != {"transaction_hash"} or not isinstance(body["transaction_hash"], str):
                        raise RequestError(400, "transaction_hash_required")
                    try:
                        result = application.payments.confirm(order_match[1], token, body["transaction_hash"])
                    except RetryLater as error:
                        return self.respond(429, {"error": "retry_later", "status_url": order["status_url"],
                                                  "confirm_url": order["confirm_url"],
                                                  "message": "Retry POST confirm with the same transaction_hash after Retry-After."},
                                            retry_after=error.seconds)
                    except Pending:
                        return self.respond(202, {"error": "payment_pending", "status": "pending", "status_url": order["status_url"],
                                                  "confirm_url": order["confirm_url"],
                                                  "message": "Retry POST confirm with the same transaction_hash after Retry-After until HTTP 200. GET status does not recheck payment."},
                                            retry_after=60)
                    except Unavailable:
                        return self.respond(503, {"error": "verification_unavailable", "status_url": order["status_url"]})
                    except PaymentError:
                        return self.respond(422, {"error": "invalid_payment_proof", "status_url": order["status_url"]})
                    return self.respond(200, application.order_urls(result))
            raise RequestError(404, "not_found")

        def route(self):
            try:
                self.dispatch()
            except RequestError as error:
                self.respond(error.status, {"error": error.code})
            except RetryLater as error:
                self.respond(429, {"error": "retry_later"}, retry_after=error.seconds)
            except Unavailable:
                self.respond(503, {"error": "service_unavailable"})
            except (socket.timeout, TimeoutError):
                try:
                    self.respond(408, {"error": "request_timeout"})
                except OSError:
                    pass
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception:
                self.respond(503, {"error": "service_unavailable"})

        do_GET = route
        do_HEAD = route
        do_POST = route

    return Handler


def make_server(host="127.0.0.1", port=8765, application=None, *, max_connections=8, request_timeout=10):
    if not 1 <= max_connections <= 64 or not 0 < request_timeout <= 120:
        raise ValueError("Invalid server limits")
    return LimitedHTTPServer((host, port), handler_for(application or StoreApplication()),
                             max_connections=max_connections, request_timeout=request_timeout)


def build_application(args):
    products = load_catalog(args.catalog_file)
    private = None
    if args.private_dir is not None:
        private = PrivateFileStore(args.private_dir, {p.id: p.asset_filename for p in products if p.asset_filename is not None})
    configured = bool(args.db_path or args.recipient or args.rpc_endpoint)
    payment_store = None
    if configured or args.enable_checkout:
        if args.db_path is None or not args.recipient or len(args.rpc_endpoint) != 2:
            raise ValueError("Payment configuration requires --db-path, --recipient, and exactly two --rpc-endpoint values")
        verifier = DualRPCVerifier(args.rpc_endpoint)
        payment_store = PaymentStore(args.db_path, args.recipient, verifier)
    return StoreApplication(private, products=products, payment_store=payment_store,
                            enable_checkout=args.enable_checkout, prefix=args.prefix)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--prefix", default="", help="Public URL prefix stripped by the reverse proxy")
    parser.add_argument("--catalog-file", type=Path)
    parser.add_argument("--private-dir", type=Path)
    parser.add_argument("--db-path", type=Path)
    parser.add_argument("--recipient", help="Public Ethereum-mainnet receiving address")
    parser.add_argument("--rpc-endpoint", action="append", default=[], help="Trusted HTTPS RPC endpoint; supply twice")
    parser.add_argument("--enable-checkout", action="store_true")
    parser.add_argument("--max-connections", type=int, default=8)
    parser.add_argument("--request-timeout", type=float, default=10)
    args = parser.parse_args()
    try:
        application = build_application(args)
        server = make_server(args.host, args.port, application, max_connections=args.max_connections,
                             request_timeout=args.request_timeout)
    except Exception:
        parser.exit(2, "Store startup failed: verify catalog, private files, database, and mainnet RPC readiness. No checkout was started.\n")
    with server:
        print("Agent Content Store started; checkout " + ("enabled" if application.checkout_enabled else "disabled"), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
