# Agent Content Store

[Visit the live store](https://marvel.sabados.ai/agent-content/) or
[read its JSON catalog](https://marvel.sabados.ai/agent-content/api/v1/catalog).
Two original fixture packs are available for **0.00010 native ETH each**, plus
Ethereum-mainnet network fees:

| Pack | Contents | Free CC0 preview |
| --- | --- | --- |
| Booking Demo v1 | 58 fictional records in JSON, CSV and SQLite, with three checked SQL journeys | Eight related rows |
| Calendar Cases v1 | 20 Australia/Sydney scheduling cases in JSON and CSV, covering DST gaps/folds, leap days, month-end policies and weekly wall-time recurrence | Three cases with expected results |

Calendar Cases includes a Python 3.9+ reference evaluator and 15 passing checks;
running it requires existing IANA timezone data. Its valid-instant examples cover
2024–2026, and each result follows an explicitly declared application policy.
Booking Demo includes its generator and 14 passing checks. Full buyer licences
are available before checkout. The paid archives are stored privately; this
repository contains the MIT-licensed store source and public sample metadata in
`example-catalog.json`.

An API-first digital-content store using Python's standard library. It serves
public product previews and delivers private files after a native Ethereum-mainnet
invoice has been paid and independently verified. People and agents use the same
API; the service does not try to prove that a visitor is an AI.

Checkout is **off by default**. Enabling it requires an installed artifact matching
its catalog SHA-256, a persistent invoice database, a public receiving address,
and two configured HTTPS RPC providers that pass the mainnet readiness check.
The service never holds wallet keys, signs transactions, or spends funds.

## Local preview

Use Python 3.10 or newer. No dependencies need installing.

```sh
python3 -B store.py --port 8765
```

Open http://127.0.0.1:8765/. The default bind is loopback and the default public
prefix is empty, so direct local links work. The built-in JSON import fixture
preview stays free and cannot be purchased.

To load a product without enabling purchases:

```sh
python3 -B store.py \
  --catalog-file /absolute/public/catalog.json \
  --private-dir /absolute/private/products
```

## Product catalog

The catalog accepts a top-level `products` array or a bare array, containing at
most 20 records. Each record has exactly these fields:

| Field | Meaning |
| --- | --- |
| `id` | Unique lowercase letters, digits, and hyphens; up to 80 characters |
| `title` | Public title, up to 200 characters |
| `description` | Public description, up to 2,000 characters |
| `price_wei` | Integer native ETH amount, greater than zero and at most one ETH |
| `asset_filename` | Plain private filename, such as `booking-demo-v1.zip` |
| `asset_sha256` | SHA-256 of the exact delivered file, 64 lowercase hexadecimal characters |
| `preview` | Public JSON object: preview rows, semantics, and full buyer licence terms |

The catalog itself is limited to 512 KB. Only explicitly public preview material
belongs in it; everything inside `preview` is served without authentication.
Publish complete licence terms in the preview before offering checkout.

Keep paid files outside this source directory and outside any web-server document
root. Private files must be regular files, not symlinks, and no larger than 2 MB.
The server has no static-directory route. It maps known product IDs to configured
filenames and rechecks the artifact digest immediately before creating each order.
A missing or changed file cannot be sold.

## Enable native ETH checkout

Use a persistent, private database path and two HTTPS endpoints operated by
independent RPC providers. Replace the illustrative paths/endpoints below with
real configuration; the example domains will not pass preflight.

```sh
python3 -B store.py \
  --host 127.0.0.1 --port 8765 \
  --catalog-file /absolute/public/catalog.json \
  --private-dir /absolute/private/products \
  --db-path /absolute/private/state/orders.sqlite3 \
  --recipient 0xb67072a78A7a59B9cD2d50605595d1Da4332b65F \
  --rpc-endpoint https://provider-one.example \
  --rpc-endpoint https://provider-two.example \
  --enable-checkout
```

Startup fails before listening if checkout is requested but the installed asset or
RPC readiness checks fail. The real CLI always constructs `DualRPCVerifier`; it
has no fake verifier, paid-status override, or manual entitlement-creation mode.
Running with the same payment configuration but without `--enable-checkout`
prevents new purchases while retaining status, confirmation, and download access
for existing orders.

## API flow

Public URL examples below use the optional `/agent-content` prefix. Without a
reverse proxy, omit that prefix. Follow the URLs returned by the API.
Send POST bodies with **`Content-Type: application/json`**. The server rejects
form-encoded data; for example, use `curl -H 'Content-Type: application/json'
--data '{}' CHECKOUT_URL` when creating an order.

1. `GET /agent-content/api/v1/catalog` lists previews, fixed prices, SHA-256 values,
   checkout availability, and endpoint URLs. Read the chosen product's preview
   and buyer licence before purchasing.
2. `POST` an empty JSON object `{}` to its `checkout_url`. HTTP **201** returns a
   pending order, a secret `bearer_token`, and an Ethereum transaction request
   containing `chainId`, `to`, `value`, and invoice-specific `data`. Client-supplied
   prices, hashes, destinations, and paid-status fields are rejected.
3. Save the bearer token. Send the exact transaction, including `data`, using
   your own authorized Ethereum-mainnet wallet. Network fees are additional.
   Token transfers, other chains, and ordinary transfers without invoice data
   cannot pay this order. Creating an order does not send any transaction.
4. `POST {"transaction_hash":"0x..."}` to `confirm_url` with
   `Authorization: Bearer <token>`. Use a real 32-byte transaction hash. If the
   response is 202 or 429, wait for `Retry-After` and **repeat the same POST with
   the same transaction hash** until it returns 200. There is no background
   verification worker: GET status alone cannot advance a pending payment.
5. Read `status_url` with the same Authorization header for saved order status.
   Once its status is
   `paid`, retrieve `download_url` with that header. ZIP files are delivered as
   `application/zip` attachments.

| Confirmation response | Meaning |
| --- | --- |
| 200 | Verified payment; order is paid |
| 202 | Receipt missing or awaiting finalization; not entitled yet |
| 422 | Invalid payment proof; no entitlement granted |
| 429 | Wait for the `Retry-After` interval before retrying |
| 503 | Verification temporarily unavailable; no entitlement granted |

Unauthenticated order/download requests return 401; incorrect credentials return
403. Tokens are returned only when an order is created, never in later status
responses. Tokens must stay in Authorization headers, not query strings. Losing
the token loses automated access; this version has no account recovery flow.

The payment module checks the exact native amount, destination, invoice data,
successful receipt, canonical block, and finalization independently through both
providers. A transaction cannot pay multiple orders. SQLite stores token hashes
and verified evidence, so entitlements survive restarts. Delivery also checks the
purchased asset's digest: replacing the file with a new version does not silently
change an existing purchase. Keep purchased artifact versions available; this
version maps one installed artifact per product ID.

## Reverse proxy and resource limits

For Kamal path routing, pass `--prefix /agent-content`. Kamal must strip that
prefix before forwarding requests; internal server routes remain `/api/v1/...`.
Every storefront link and returned endpoint URL includes the configured public
prefix. Use `/api/v1/catalog` as the upstream health-check path.

Bind the service to an address reachable by the proxy. A Docker proxy cannot
reach the host's loopback listener. On the current `quant` layout, a host service
can bind specifically to its verified Docker bridge address, or a
separate container can listen on its own interface within the same Docker network.
Do not expose the private artifact directory through the proxy.

The server bounds active connections to 8 and socket read/write inactivity to
10 seconds by default (`--max-connections`, `--request-timeout`). Request bodies
are limited to 2 KB and must be strict JSON, without duplicate members, non-finite
numbers, or transfer encoding. Excess connections receive 503. Responses disable
caching. Request headers, tokens, body contents, and backend exception details
are not logged. RPC calls have their own 10-second per-call timeout; verification
uses several calls, so configure the proxy target timeout to accommodate them
(for example, 120 seconds).

This small standard-library HTTP service needs an HTTPS reverse proxy for public
use. It relies on the configured RPC operators and does not run its own Ethereum
node. Two different hostnames alone do not prove provider independence; verify
operator ownership when configuring endpoints. There is no refund automation,
account recovery, or high-volume capacity management. The SQLite database and
paid artifacts require private backups. Only native mainnet ETH checkout is
implemented; no Bitcoin payment method is advertised.

## Tests

```sh
python3 -B -m unittest discover -s tests -v
python3 -B -m unittest test_payments -v
```

HTTP integration tests use a real local server and SQLite database, synthetic ZIP
files, and a fake read-only verifier confined to the tests. They cover invoices,
pending/rejected/unavailable/paid states, restart persistence, product and artifact
binding, denied static paths, strict request bodies, connection limits, and
timeouts. Payment-module tests separately exercise the real verifier against
synthetic RPC responses. Neither suite uses wallet keys or moves funds.
