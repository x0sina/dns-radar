# DNS Radar (Go)

Find DNS resolvers that work for `dnstt/slipstream` long-domain TXT traffic.

## Quick Setup

1. Create DNS TXT record(s) on your domain.
2. Fill `.env` from `.env.example`.
3. Put resolver IPs in `ips.txt`.
4. Run scanner.
5. Read `good.txt`.

### 1) DNS record setup (example with Cloudflare)

Use domain `example.com`.

Create:
- record name: `*.probe`
- type: `TXT`
- value: `slipstream-ok`
- mode: `DNS only`

Then use:
- `TXT_BASE_DOMAIN=probe.example.com`
- `TXT_EXPECTED_TOKEN=slipstream-ok`

Why wildcard: scanner generates many long subdomains under `probe.example.com`.

### 2) Create `.env`

Copy `.env.example` to `.env` and edit values.

Required:
- `TXT_BASE_DOMAIN=probe.example.com`

Recommended:
- `TXT_EXPECTED_TOKEN=slipstream-ok`

### 3) Input list

Create `ips.txt` (one DNS resolver IP per line).

### 4) Run

From `dns-radar` folder:

```bash
go run ./cmd/scanner
```

Build binary:

```bash
go build -o dns-radar ./cmd/scanner
./dns-radar
```

## Output

- default output file: `good.txt`
- one good resolver IP per line
- detailed CSV file: `good.csv`

## Environment variables

- `TXT_BASE_DOMAIN` (required)
- `TXT_EXPECTED_TOKEN` (optional)
- `IPS_FILE` (default: `ips.txt` or `../ips.txt`)
- `SUCCESS_FILE` (default: `good.txt` or `../good.txt`)
- `SUCCESS_CSV_FILE` (default: `good.csv` or `../good.csv`)
- `DNS_QUERY_COUNT` (default `5`)
- `DNS_MIN_SUCCESS` (default `4`)
- `DNS_MIN_LENGTH` (default `152`)
- `DNS_MAX_LENGTH` (default `253`)
- `DNS_MIXED_CASE` (default `true`)
- `PING_TIMEOUT_MS` (default `2000`)
- `DNS_TIMEOUT_MS` (default `2000`)
- `SCAN_CONCURRENCY` (default `64`)

## Common error

`TXT_BASE_DOMAIN is required` means scanner did not get this value.

Fix:
- make sure `.env` exists in `dns-radar`
- set `TXT_BASE_DOMAIN=probe.example.com` in `.env`
- run again
