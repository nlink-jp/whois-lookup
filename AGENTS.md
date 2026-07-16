# AGENTS.md — whois-lookup

## What this is

A CLI + (Phase 2) local MCP server that reports the **registration data** of
a domain, IP address, or AS number: registrar, creation/update/expiry dates,
nameservers, abuse contact. **RDAP-first**: endpoints are resolved via the
IANA bootstrap registry (`https://data.iana.org/rdap/`, ETag-cached) and
queried over HTTPS for structured JSON; ccTLDs without RDAP (including .jp)
fall back to raw port 43 WHOIS with referral chasing. Zero credentials, zero
external dependencies. The registration-focused sibling of `asn-lookup`
(attribution), `abuse-lookup` (reputation), and `tor-exit-lookup` (Tor exit
membership).

## Build & test

```bash
make build      # → dist/whois-lookup  (NEVER `go build` directly)
make test       # go test -race -cover ./...
make check      # lint + test + build-all
make build-all  # cross-compile linux/{amd64,arm64}, darwin/arm64, windows/amd64
```

Go 1.25+. **No external dependencies** — standard library only.

## Layout

```
main.go                 Entry point; sets main.version, calls app.Run.
internal/query/         Input classification + domain-syntax validation gate.   (Phase 1)
internal/bootstrap/     IANA bootstrap fetch + ETag conditional-GET cache.      (Phase 1)
internal/rdap/          RDAP client (domain/ip/autnum), lenient decode.         (Phase 1)
internal/whois/         Port 43 fallback + referral chasing, raw-first.         (Phase 2)
internal/idn/           In-house RFC 3492 punycode (U-label → A-label).         (Phase 2)
internal/cache/         Per-query TTL cache (24h default), atomic writes.       (Phase 1)
internal/config/        Sectioned-TOML subset + WHOIS_LOOKUP_* env/flags.       (Phase 1)
internal/engine/        validate → cache → bootstrap → rdap → whois → normalize.(Phase 1)
internal/app/           CLI dispatch; lookup/cache/mcp; --type/--json/--raw.
internal/mcp/           Zero-dep stdio JSON-RPC 2.0 server + tools.             (Phase 2)
```

## Key design decisions

- **RDAP-first, WHOIS fallback-only.** RDAP gives structured JSON, is
  ICANN-mandated for gTLDs, and covers all five RIRs. Port 43 exists solely
  for ccTLDs without RDAP; its raw text is returned as the primary result
  with only a loose key:value extraction (no full parser).
- **Validation gate before any network I/O.** Not-IP, not-ASN input must
  pass RFC hostname validation (≤253 total, labels 1–63 LDH, dot required,
  control chars/CRLF rejected) or the request is refused: CLI exits 2, MCP
  returns `{code: "invalid_input", ...}`. This blocks CRLF injection into
  the port 43 protocol, wasted rate limits, and cache-key pollution.
- **No credentials.** Every endpoint is public; nothing to configure or leak.
- **Engine is shared** by CLI and MCP so their behaviour cannot diverge; the
  HTTP client and port 43 dialer are injected interfaces, mocked in tests.
- **Cache keys are canonical** (A-label domains, canonical IPs) so
  `日本語.jp` and `xn--wgv71a119e.jp` share one entry. TTL default 24h —
  WHOIS data changes slowly and registries rate-limit hard.
- **IDN in-house.** RFC 3492 punycode encoder (~150 lines) instead of
  `x/net/idna`; simplified IDNA (lowercase only, input assumed NFC).
  `query_ascii` accompanies the original input in output.
- **Output states its source** (`rdap` | `whois`) and never promises
  registrant personal data (GDPR redaction since 2018).

## Gotchas

- **Exit-code contract (lookup):** `0` success / `1` object not found (RDAP
  404, WHOIS "no match") / `2` error. Not grep-style — a not-found is a
  successful answer about a nonexistent object, distinct from failure.
- **RDAP dialects:** registries differ in optional fields; decode leniently
  and normalize in one place (internal/rdap). Don't let one registry's
  quirks leak into the schema.
- **Thin registries:** .com/.net registry WHOIS/RDAP lacks registrant
  detail; follow `Registrar WHOIS Server:` / RDAP `links` to the registrar
  when chasing details.
- **Fetch etiquette:** never retry aggressively; respect the cache. The
  bootstrap files change rarely — ETag conditional GET keeps revalidation
  free.
- **Status: scaffold only.** `lookup` / `cache` / `mcp` are stubs returning
  exit 2. Phase 1 (validation, bootstrap, RDAP, cache, lookup) is next.

## Data sources

- `https://data.iana.org/rdap/{dns,ipv4,ipv6,asn}.json` — RDAP bootstrap
  (public, ETag-cached locally).
- RDAP endpoints of RIRs / registries / registrars (public, resolved via
  bootstrap).
- `whois.iana.org:43` referral chain (public; fallback for TLDs without
  RDAP).
