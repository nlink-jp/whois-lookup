# whois-lookup

Look up the registration data of a **domain, IP address, or AS number** —
registrar, creation/update/expiry dates, nameservers, and abuse contact —
from the command line or as a local MCP server.

**RDAP-first**: queries go to the official RDAP endpoints (structured JSON,
resolved via the IANA bootstrap registry), falling back to raw port 43 WHOIS
only for ccTLDs without RDAP. **Zero credentials, zero external
dependencies** — every data source is a public endpoint, and the binary is
standard library only.

The registration-focused sibling of
[asn-lookup](https://github.com/nlink-jp/asn-lookup) (attribution, offline),
[abuse-lookup](https://github.com/nlink-jp/abuse-lookup) (reputation), and
[tor-exit-lookup](https://github.com/nlink-jp/tor-exit-lookup) (Tor exit
membership) — together they profile an indicator from four angles.

> **Status: in development (pre-release).** Phases 1 and 2 are implemented:
> RDAP lookups, the port 43 WHOIS fallback (RDAP-less ccTLDs such as .jp),
> in-house IDN punycode conversion, the `cache` subcommand, and the MCP
> server. Remaining: Phase 3 (release). See
> [docs/en/whois-lookup-rfp.md](docs/en/whois-lookup-rfp.md) for the full
> design.

## Usage

```console
$ whois-lookup lookup example.com
$ whois-lookup lookup 93.184.216.34 --json
$ whois-lookup lookup AS13335
$ whois-lookup lookup 日本語.jp        # IDN → punycode in-house; .jp → WHOIS fallback
$ whois-lookup cache status
$ whois-lookup mcp                     # local MCP server (stdio)
```

`lookup` exit codes: `0` success, `1` the object does not exist (RDAP 404),
`2` error (invalid input, network failure).

- Input type (IP / ASN / domain) is auto-detected; `--type` overrides.
- Input that is valid as none of the three is **rejected before any network
  I/O** — a safety gate against protocol injection and wasted rate limits.
- Results are cached locally (default TTL 24h); `--refresh` bypasses.
- `--raw` includes the raw payload: `raw` (RDAP JSON) or `raw_text` (WHOIS).
- Output states its `source` (`rdap` or `whois`) and, for IDN queries, the
  punycoded `query_ascii` form.
- The MCP server exposes `lookup`, `cache_status`, and `get_usage`; tool
  errors are structured (`{code, message}`).

**What you can expect back:** since GDPR (2018), most registrant personal
data is redacted ("REDACTED FOR PRIVACY"). The reliably available fields are
registrar, dates, nameservers, status, and — for IP/ASN queries — the RIR,
network name, allocation range, and abuse contact.

## Build & test

```bash
make build   # → dist/whois-lookup   (never `go build` directly)
make test    # go test -race -cover ./...
```

Go 1.25+. No external dependencies.

## Configuration

Optional — everything works with defaults. Copy
[config.example.toml](config.example.toml) to
`~/.config/whois-lookup/config.toml` to override the cache TTL, cache
directory, bootstrap URL, or network timeout. No credentials exist.

## Data sources

- IANA RDAP bootstrap registry: <https://data.iana.org/rdap/> (public)
- RDAP endpoints of the RIRs, registries, and registrars (public)
- Port 43 WHOIS referral chain rooted at `whois.iana.org` (public, fallback
  only)

## License

MIT — see [LICENSE](LICENSE).
