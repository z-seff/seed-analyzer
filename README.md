# Seed Analyzer

The script takes a BIP39 seed phrase (12/15/18/21/24 words), derives the first N
addresses for seven derivation schemes, checks balances via public RPCs across
six EVM networks, Tron and Bitcoin, and writes the result to an xlsx report.

> **Note:** the tool's own console output and the generated xlsx report are in
> Russian (hardcoded strings/column headers). Only this documentation has been
> translated to English; example output blocks below are reproduced verbatim.

## Contents

| File | Purpose |
|------|---------|
| `seed_analyzer.py` | the script itself |
| `requirements.txt` | dependencies: `bip_utils`, `openpyxl`, `requests` |

## Derivation schemes

| Network  | Scheme | Path                 | Address type             |
|----------|--------|----------------------|---------------------------|
| EVM      | BIP44  | `m/44'/60'/0'/0/i`   | `0x...`                  |
| Tron     | BIP44  | `m/44'/195'/0'/0/i`  | `T...`                   |
| Bitcoin  | BIP44  | `m/44'/0'/0'/0/i`    | P2PKH `1...`             |
| Bitcoin  | BIP49  | `m/49'/0'/0'/0/i`    | P2SH-P2WPKH `3...`       |
| Bitcoin  | BIP84  | `m/84'/0'/0'/0/i`    | P2WPKH `bc1...`          |
| Bitcoin  | BIP32  | `m/0/i`              | P2PKH `1...`             |
| Bitcoin  | BIP141 | `m/0/i`              | P2WPKH nested in P2SH `3...` |

`i` is the address index from 0 to `--count - 1`. For BIP44/49/84 it's the last
path level after `change`; for BIP32 and BIP141 it's a direct child of the
`m/0` node.

Paths and address types for the BIP32 and BIP141 tabs are taken from the
[iancoleman.io/bip39](https://iancoleman.io/bip39/) defaults: path `m/0`,
script semantics "P2WPKH nested in P2SH". The `account'` number for
BIP44/49/84 is changed with the `-a` flag.

Derivation has been checked against the reference BIP39 test vectors for the
phrase `abandon abandon ... about` — all addresses match.

## EVM networks

The EVM address is the same across all networks, so derivation happens once,
and the address is checked in each selected network as a separate report row.
Balance, nonce, and all network tokens are fetched with a **single** batch
JSON-RPC request: the delay is spent per address, not per token.

| Key       | Network    | chainId | Native | Tokens                   | RPC |
|-----------|------------|---------|--------|--------------------------|-----|
| `eth`     | Ethereum   | 1       | ETH    | USDT, USDC, DAI          | `ethereum-rpc.publicnode.com` |
| `arb`     | Arbitrum   | 42161   | ETH    | USDC, USDC.e, USDT       | `arbitrum-one-rpc.publicnode.com` |
| `base`    | Base       | 8453    | ETH    | USDC, USDT               | `base-rpc.publicnode.com` |
| `polygon` | Polygon    | 137     | POL    | USDC, USDC.e, USDT, WETH | `polygon-bor-rpc.publicnode.com` |
| `avax`    | Avalanche  | 43114   | AVAX   | USDC, USDT, WETH.e       | `avalanche-c-chain-rpc.publicnode.com` |
| `op`      | OP Mainnet | 10      | ETH    | USDC, USDC.e, USDT       | `optimism-rpc.publicnode.com` |

Where ETH is not the native coin (Polygon, Avalanche), its wrapped version is
checked instead — WETH and WETH.e. Bridged `.e` versions of USDC are checked
on equal footing with the native ones: on these networks, older wallets more
often hold their balance there.

All 18 contracts have been verified on-chain via `symbol()` and `decimals()`
calls, and each RPC's chainId has been checked too. On Arbitrum and Polygon,
USDT's `symbol()` returns `USD₮0` / `USDT0` — this is a Tether rebrand, the
contract itself remains canonical.

**Network keys for `-c`:** `eth`, `arb`, `base`, `polygon`, `avax`, `op`, `trx`, `btc`.
**Aliases:** `ethereum`, `mainnet`, `arbitrum`, `arbitrum-one`, `matic`, `pol`,
`avalanche`, `avalanche-c`, `optimism`, `op-mainnet`, `tron`, `bitcoin`.
**Groups:** `evm` — the six EVM networks, `all` — the same plus Tron and Bitcoin (default).

Case and extra whitespace don't matter, duplicates are collapsed, and the
report order is always canonical — EVM networks, then Tron, then Bitcoin.

## Installation

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

`bip_utils` doesn't build on Python 3.14 (the `coincurve` dependency build
fails); you need 3.10–3.12.

## Usage

```bash
# enter the phrase via a hidden prompt (won't end up in shell history)
.venv/bin/python seed_analyzer.py

# addresses only, no network requests — quick check against a generator
.venv/bin/python seed_analyzer.py --dry-run -m "..."

# find a specific address among the generated ones
.venv/bin/python seed_analyzer.py --dry-run -m "..." --find 0xAbC...

# only L2s and Bitcoin, 100 addresses per scheme
.venv/bin/python seed_analyzer.py -m "..." -c arb,base,op,btc -n 100
```

### Flags

| Flag | Purpose |
|------|---------|
| `-m, --mnemonic` | seed phrase in quotes |
| `-f, --mnemonic-file` | file containing the phrase |
| `-p, --passphrase` | BIP39 passphrase (extra word) |
| `-n, --count` | addresses per scheme, default 50 |
| `-d, --delay` | delay between requests in seconds, default 3 |
| `-a, --account` | `account'` number for BIP44/49/84, default 0 |
| `-c, --chains` | comma-separated networks or the `evm`/`all` group, default `all` |
| `-o, --out` | xlsx file name; auto-generated by default |
| `--overwrite` | overwrite the existing file instead of adding a suffix |
| `-v, --verbose` | print every checked address, not just the notable ones |
| `--find ADDR` | search for address(es), comma-separated, among the generated ones |
| `--keep-empty` | don't hide empty rows in the report |
| `--with-keys` | export private keys to the xlsx (disabled by default) |
| `--dry-run` | derivation only, no network |
| `--no-validate` | skip the BIP39 checksum validation |

The phrase is taken from `-m`, otherwise from `-f`, otherwise it's requested
via a hidden prompt. The word count and BIP39 checksum are validated before
any network requests.

Exit codes: `0` — success, `2` — argument error or invalid phrase,
`130` — interrupted with Ctrl+C.

### Report file name

Without `-o` the name is generated automatically so that runs don't overwrite
each other:

```
seed_report_2026-09-23_14-05-33_all_n500.xlsx
            └── date ──┘ └time─┘ └net┘ └count┘
```

The networks segment contains `all`, `evm`, or a hyphen-separated list of the
selected keys (`base-btc`, `arb-base-op-btc`). The phrase itself, or anything
derived from it, never ends up in the file name.

An existing file is never overwritten: both with an auto-generated name and
with an explicit `-o`, `_2`, `_3`, etc. is appended to the name, and a message
is printed about it. Use `--overwrite` to overwrite instead. The absolute path
is printed when the run finishes.

### Progress indicator

A network run prints a live line that updates in place (actual output, in Russian):

```
[247/600]  41.2% | прошло 12м 21с | осталось ~17м 39с | с активами: 3
```

(`elapsed 12m 21s | remaining ~17m 39s | with assets: 3`)

The remaining-time estimate is based on actual throughput rather than
`--delay`, so it accounts for retries and slow RPCs. Only notable addresses
get their own log line — those with history, with assets, with a request
error, or found via `--find`; empty ones don't appear in the output.
Previously a line was printed for every address, i.e. 6000 lines at `-n 500`.

The `-v` flag restores the old behavior — a line for every checked address.
If output is redirected to a file, the live line is replaced with a plain
entry every 25 addresses, with no control characters.

### Address search: `--find`

Accepts one address or several comma-separated, case-insensitive. The search
runs over the **full** set of generated addresses, right after derivation and
**before** empty rows are hidden, so a found address always ends up in the
report — even if it's empty and has no history. Such a row is highlighted in
blue in the report and flagged in the "Status" column.

The result notice is printed **twice**: right after address generation and
again at the end of the run — otherwise it would get lost among hundreds of
progress lines. For each searched address, a found/not-found line is printed
with the scheme, path, index, and list of networks (actual output, in Russian):

```
──────────────────────────────────────────────────────────────────────────────
ПОИСК --find: найдено 2 из 3 среди 600 сгенерированных адресов
──────────────────────────────────────────────────────────────────────────────
  ✓ НАЙДЕН      0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0
                BIP44  m/44'/60'/0'/0/1  (индекс 1)
                сети: Ethereum, Arbitrum, Base, Polygon, Avalanche, OP Mainnet
                активы: Ethereum 0.05000000 ETH; Polygon USDC=120.000000
  ✗ НЕ НАЙДЕН   0xdeadbeef00000000000000000000000000000000
  Проверено 12 схемо-сетей × 50 адресов, account' = 0, passphrase не задан.
  Если адрес всё же от этой фразы — увеличьте -n, проверьте -a и -p, а также набор сетей в -c.
──────────────────────────────────────────────────────────────────────────────
```

(`ПОИСК --find` = search results; `✓ НАЙДЕН` / `✗ НЕ НАЙДЕН` = found / not
found; `сети` = networks; `активы` = assets; the closing lines report how many
scheme/network combinations × addresses were checked and suggest raising `-n`
or checking `-a`/`-p`/`-c` if the address should belong to this phrase.)

In the second notice, after the networks have been polled, the assets of the
found address are additionally shown, and if some network didn't respond, a
`не проверено (ошибка RPC)` ("not checked, RPC error") line is shown with its
name — so that "no assets" isn't mistaken for a confirmed zero balance.

The address is printed in its canonical form, as produced by derivation: you
can search in any case, and an EVM address will be displayed with checksum
casing. A single EVM address matches across all selected EVM networks at
once — that's one derivation row, so the networks are listed in a single
entry rather than duplicated.

If a found address could not be verified, the "Status" column will show both
flags at once: `НАЙДЕН по --find; ОШИБКА: ...` ("found via --find; ERROR: ...").

Also works together with `--dry-run`, if you just need to know whether an
address belongs to this phrase and at what path it's derived — without a
single network request. In this mode, `--dry-run --find` does not print the
line-by-line address list: at `-n 500` that's 6000 lines, which would
completely bury the notice. The full list still ends up in the xlsx. Without
`--find`, the list is printed as before.

Without `--find`, no search notices are printed.

### Hiding empty rows

By default, rows with no assets and no transaction history are removed from
the `Addresses` sheet. A row stays if at least one of these holds:

- a nonzero native coin balance;
- a nonzero balance of any checked token;
- there was activity — nonce > 0 on EVM, tx_count > 0 on Bitcoin, an activated
  account on Tron;
- the request failed (otherwise a broken RPC would look like an empty address);
- the address matched `--find`.

Disabled via `--keep-empty`. In `--dry-run` mode the filter isn't applied —
there's nothing to filter by. The `Summary` sheet is always computed over the
full set of addresses and shows, in a separate column, how many rows were hidden.

## Public RPCs and run time

| Network | Endpoint | What's fetched |
|---------|----------|-----------------|
| EVM  | `publicnode.com` (see table above) | balance, nonce, ERC20 — in a single batch request |
| Tron | `api.trongrid.io` | TRX balance, all TRC20 |
| Bitcoin | `blockstream.info/api` | balance (chain + mempool), transaction count |

The delay is enforced globally between **all** HTTP requests: one request per
report row. Retries (up to 3 attempts on timeout, 429, and 5xx) use the same
delay, so a problematic RPC will stretch out the run.

Number of requests = (number of selected EVM networks + Tron + 5 Bitcoin schemes) × `--count`:

| `-c` | Requests at `-n 50` | Time at `-d 3` | Time at `-d 10` |
|------|----------------------|------------------|-------------------|
| `all` | 600 | ≈ 30 min | ≈ 100 min |
| `evm` | 300 | ≈ 15 min | ≈ 50 min |
| `btc` | 250 | ≈ 12 min | ≈ 42 min |
| `eth,trx` | 100 | ≈ 5 min | ≈ 17 min |

Progress is printed line by line, `•` marks an address with history. You can
interrupt with Ctrl+C, but then the xlsx isn't saved — for a short trial,
lower `-n` instead.

## Report

**`Addresses` sheet** — one row per address × network pair: network, scheme,
derivation path, index, address, balance, coin, transaction count, tokens,
usage flag, status, and, with `--with-keys`, the private key. Includes
autofilter and a frozen header row.

Row highlighting:

| Color | Meaning |
|--------|---------|
| blue | found via `--find` |
| green | has assets — balance or tokens |
| yellow | address was used but is currently empty |
| orange | request error, data unreliable |

**`Summary` sheet** — for each network/scheme pair: how many addresses were
checked, how many had history, how many had assets, how many empty ones were
hidden, how many errors, total balance. Computed over the full set of
addresses, so it's unaffected by filtering.

## Security

- The phrase is never stored anywhere; without `-m` it's entered via a hidden
  prompt so it doesn't end up in shell history.
- Only addresses go out over the network. Private keys and the phrase — never.
- `--with-keys` puts private keys into a plain xlsx file — use it only on an
  offline machine and delete the file afterwards.
- Public RPCs see your IP together with the whole set of addresses, i.e. they
  can link them together. If that matters, use your own node or a VPN.
- The script only reads network state: it never signs or sends a single
  transaction.
