# CLAUDE.md — whois-lookup

**Organization rules (mandatory): https://github.com/nlink-jp/.github/blob/main/CONVENTIONS.md**

## Purpose

CLI + local MCP server that reports the **registration data** of a domain,
IP address, or AS number: registrar, creation/update/expiry dates,
nameservers, and abuse contact. **RDAP-first** (IANA bootstrap → structured
JSON over HTTPS) with a **port 43 WHOIS fallback** only for ccTLDs without
RDAP (including .jp). Zero credentials, zero external dependencies. The
registration-focused sibling of `asn-lookup` (attribution, offline),
`abuse-lookup` (reputation), and `tor-exit-lookup` (Tor exit membership).

## Build & test

```bash
make build       # Build → dist/whois-lookup  (never `go build` directly)
make test        # Tests with race detector + coverage
go test ./...    # Same without Makefile
```

## Architecture

```
main.go                 CLI entry: main.version → app.Run
internal/query/         Input classification + RFC domain-syntax validation gate (Phase 1)
internal/bootstrap/     IANA RDAP bootstrap fetch + ETag conditional-GET cache (Phase 1)
internal/rdap/          RDAP client: domain/ip/autnum, lenient decode, normalization (Phase 1)
internal/whois/         Port 43 fallback + referral chasing, raw-first output (Phase 2)
internal/idn/           In-house RFC 3492 punycode encoder, U-label → A-label (Phase 2)
internal/cache/         Per-query TTL cache (default 24h), atomic writes (Phase 1)
internal/config/        Sectioned-TOML subset + WHOIS_LOOKUP_* env/flag resolution (Phase 1)
internal/engine/        validate → cache → bootstrap → rdap → whois fallback → normalize (Phase 1)
internal/app/           Dispatch + lookup/cache/mcp; --type/--json/--raw/--refresh
internal/mcp/           Zero-dep stdio JSON-RPC 2.0 server (lookup/cache_status/get_usage) (Phase 2)
```

Core logic takes injected dependencies (the HTTP client and the port 43
dialer are interfaces, mocked in tests). **No external dependencies —
standard library only.**

## Key conventions

- **Validation gate is a safety mechanism, not UX.** Input that is valid as
  none of IP / ASN / domain is rejected **before any network I/O**. Port 43
  is a raw "query + CRLF" protocol, so CRLF/control characters in input are
  a protocol-injection vector; the gate also prevents wasted rate limits and
  cache-key pollution. Never send unvalidated input to the network.
- **RDAP is authoritative; WHOIS is a fallback.** A TLD absent from the IANA
  bootstrap (or a bootstrap 404) triggers port 43 — never the other way
  around. Output always states `source: rdap|whois`.
- **No credentials.** Every endpoint is public. There is no token or API key
  to configure, log, or leak — unlike asn-lookup (ipinfo token) or
  abuse-lookup (AbuseIPDB key).
- **Cache is etiquette.** Registries rate-limit hard (especially port 43).
  Per-query TTL default 24h; bootstrap files revalidate with ETag
  conditional GET. Cache keys use the canonical form (A-label, canonical IP).
- **IDN without x/net/idna.** In-house RFC 3492 punycode encoder (~150
  lines), lowercasing-only simplified IDNA; UTS #46/bidi out of scope. Input
  assumed NFC-normalized.
- **Exit codes (lookup):** `0` success / `1` object not found (RDAP 404,
  WHOIS no match) / `2` error.
- **Engine is shared** by CLI and MCP so their behaviour cannot diverge.
- **GDPR expectations:** most registrant data is redacted; READMEs must not
  promise personal registrant details.

## Status

v0.1.0 released (Phases 1 + 2): RDAP lookups with caching, port 43 WHOIS
fallback for RDAP-less ccTLDs, IDN punycode, `cache status|clear`, and the
stdio MCP server. Design:
[docs/ja/whois-lookup-rfp.ja.md](docs/ja/whois-lookup-rfp.ja.md).

## Communication Language

All communication between contributors and Claude Code is conducted in
**Japanese**.
