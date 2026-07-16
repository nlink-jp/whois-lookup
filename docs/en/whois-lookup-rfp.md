# RFP: whois-lookup

> Generated: 2026-07-16
> Status: Draft

## 1. Problem Statement

During incident response and OSINT investigations there is a frequent need to
check the registration data of a domain, IP address, or AS number (registrar,
creation/update/expiry dates, nameservers, abuse contact). The classic `whois`
command returns registry-specific, unstructured text, while commercial WHOIS
APIs require credentials and fees.

whois-lookup is a CLI and MCP server that returns structured registration data
with **zero credentials, one command**, by using the official and free RDAP
protocol (RFC 7480ff.) as the primary path and falling back to port 43 WHOIS
only for ccTLDs without RDAP. Target users are the operator and Claude (via
MCP) performing investigations.

Positioning among siblings: asn-lookup answers "which AS does this IP belong
to" (offline, fast); whois-lookup answers "what are the registration details
and contacts for that allocation" (online, detailed).

## 2. Functional Specification

### Commands / API Surface

CLI:

- `whois-lookup lookup <ip|domain|ASn>` — auto-detects the input type
  - `--type ip|domain|asn` — explicit type override
  - `--json` — JSON output (default is human-readable text)
  - `--raw` — include the raw WHOIS text / raw RDAP response
  - `--refresh` — bypass the cache and re-fetch
  - `--timeout <dur>` — network timeout
- `whois-lookup cache status` — cache statistics (entries, bootstrap freshness)
- `whois-lookup cache clear` — clear the query cache
- `whois-lookup mcp` — start the MCP server (stdio)
- `whois-lookup version`

MCP tools (skeleton ported from data-toolbox-mcp):

- `lookup` — same logic as the CLI lookup (query, type?, raw?, refresh?)
- `cache_status` — cache state
- `get_usage` — tool reference and error-recovery table

### Input / Output

Input detection: if `netip.ParseAddr` succeeds it is an IP (v4/v6); if it
matches `^AS\d+$` (case-insensitive) it is an ASN. Anything else is treated
as a domain **only if it passes domain syntax validation**; input that
qualifies as none of the three is rejected with an error before anything is
sent to the network (safety gate).

Domain syntax validation (RFC-compliant hostname check):

- Normalization: trim surrounding whitespace, lowercase, strip trailing dot
- Total length ≤ 253 characters; each label 1–63 characters
- Labels are LDH (letters, digits, hyphen; no leading/trailing hyphen)
- Must contain at least one dot (a bare TLD is allowed only with an explicit
  `--type domain`)
- Input containing control characters, whitespace, or CRLF is rejected
  outright — port 43 is a raw "query + CRLF" protocol, so embedded CRLF is a
  direct protocol-injection vector
- IDN (e.g. Japanese domains): labels containing non-ASCII characters are
  converted to A-labels (`xn--`) by an in-house punycode implementation
  (RFC 3492, zero dependencies) before validation; LDH validation then applies
  to the converted labels. Already-punycoded input is accepted as-is. Cache
  keys and queries use the A-label form (`日本語.jp` and
  `xn--wgv71a119e.jp` share one cache entry). Phase 1 accepts A-labels only;
  U-label conversion lands in Phase 2

On validation failure: nothing is sent to the network; the CLI exits non-zero
with a clear reason, and MCP returns a structured tool error
`{code: "invalid_input", message, details}`. This also prevents wasting rate
limits and polluting cache keys.

Output JSON schema (main fields):

```json
{
  "query": "日本語.jp",
  "query_ascii": "xn--wgv71a119e.jp",
  "type": "domain",
  "source": "rdap",
  "registrar": "...",
  "created": "...", "updated": "...", "expires": "...",
  "nameservers": ["..."],
  "status": ["..."],
  "abuse_contact": {"name": "...", "email": "..."},
  "raw": "(only with --raw)"
}
```

- `source` always states `rdap` | `whois`
- For IP/ASN queries the result carries the RIR, network name, allocation
  range, and abuse contact (from the RDAP vCard) instead of a registrar
- On the WHOIS fallback path the raw text is the primary result, with a
  best-effort loose key: value extraction attached (no full parser)

### Resolution flow

1. Fetch the IANA RDAP bootstrap files (`dns.json` / `ipv4.json` /
   `ipv6.json` / `asn.json`) with ETag conditional GET and cache locally;
   resolve the endpoint
2. RDAP query (HTTPS + JSON)
3. Only when the TLD has no RDAP (absent from bootstrap / 404), fall back to
   port 43 WHOIS: `whois.iana.org` → `refer:` → registry → (for thin
   registries) `Registrar WHOIS Server:` → registrar

### Configuration

- Sectioned TOML: `~/.config/whois-lookup/config.toml` (following the existing
  config conventions)
- Settings: query-cache TTL (default 24h), bootstrap revalidation interval,
  timeout, cache directory
- Overridable via env vars (`WHOIS_LOOKUP_*`)
- Cache storage: `~/.cache/whois-lookup/`

### External Dependencies

- Go library dependencies: **zero** (`net/http`, `net`, `net/netip`,
  `encoding/json` only)
- Network targets: IANA (bootstrap / port 43 referral root) and the RDAP /
  WHOIS endpoints of RIRs, registries, and registrars — all public,
  unauthenticated services

## 3. Design Decisions

- **RDAP-first**: structured JSON, mandated by ICANN for gTLDs (since 2019),
  fully supported by all five RIRs (ARIN/RIPE/APNIC/LACNIC/AFRINIC). Raw
  WHOIS parsing is not the primary path
- **Port 43 as fallback only**: kept solely because many ccTLDs (including
  .jp) do not provide RDAP. The protocol is ~30 lines with `net` alone
- **Zero credentials**: same operational feel as tor-exit-lookup /
  icloud-relay-lookup. Commercial WHOIS APIs (WhoisXML etc.) are rejected —
  they charge for what RDAP provides free and officially
- **No external whois library**: violates the zero-dependency policy and adds
  little over the in-house implementation
- **IDN via simplified IDNA + in-house punycode**: no `x/net/idna`; an
  in-house RFC 3492 punycode encoder (~150 lines). Mapping is simplified to
  lowercasing only — full UTS#46 mapping, bidi rules, and contextual rules
  are out of scope (README states that input is assumed NFC-normalized).
  The output JSON includes `query_ascii` (A-label form) alongside the
  original input
- **Cache design**: per-query TTL cache ported from abuse-lookup; ETag
  conditional GET for bootstrap ported from icloud-relay-lookup
- **Out of scope**: commercial API integration, a full raw-WHOIS parser,
  WHOIS history, bulk-query optimization, reverse whois

## 4. Development Plan

### Phase 1: Core

- Input detection + syntax-validation gate (IP / ASN / domain; invalid input
  rejected before any network I/O)
- IANA bootstrap fetch + ETag conditional GET cache
- RDAP client (domain / ip / autnum)
- Per-query TTL cache
- `lookup` subcommand + `--json`
- Tests: full path coverage via injected mock HTTP client

### Phase 2: Features

- Port 43 WHOIS fallback with referral chasing (iana → registry → registrar)
- IDN support: in-house punycode (RFC 3492) encoder for U-label → A-label
  conversion (tested against the RFC's sample vectors plus real Japanese
  domains)
- `--raw` / loose key:value extraction
- `cache status|clear` subcommands
- MCP server (`lookup` / `cache_status` / `get_usage`)

### Phase 3: Release

- README.md / README.ja.md / CHANGELOG.md / AGENTS.md
- `make build-all` (4 platforms) + macOS signing & notarization
- 12-step release process (upload zips one by one)
- cybersecurity-series submodule, org profile, web site catalog,
  homebrew-tap, check-org.sh

Phases 1 and 2 can be reviewed independently.

## 5. Required API Scopes / Permissions

None. All data sources (RDAP / WHOIS endpoints of IANA, RIRs, registries,
registrars) are public, unauthenticated endpoints.

## 6. Series Placement

Series: **cybersecurity-series**

Reason: same shelf as the investigation-oriented lookup siblings
(abuse-lookup / tor-exit-lookup / icloud-relay-lookup). The primary use case
is IR/OSINT investigation, so it belongs with the security tools rather than
util-series.

## 7. External Platform Constraints

- **Registry rate limits**: strict, especially on port 43 (e.g. Verisign).
  The TTL cache (default 24h) is mandatory, also as a courtesy; retries are
  conservative
- **GDPR redaction**: since 2018 most registrant personal data is
  "REDACTED FOR PRIVACY". The README must state that the obtainable data is
  mainly registrar / dates / nameservers / status / abuse contact
- **ccTLDs without RDAP**: many, including .jp — the fallback path is a
  required feature
- **IANA bootstrap changes rarely**: ETag conditional GET works well
- **RDAP response dialects**: optional fields vary across registry
  implementations. Decode leniently, normalize in the output schema

---

## Discussion Log

- 2026-07-16: Initial consultation. Compared (a) raw-WHOIS-centric, (b)
  external whois library, (c) commercial API, (d) RDAP-first with WHOIS
  fallback; adopted (d) as the only design satisfying structured output,
  zero credentials, and zero dependencies simultaneously
- Series placement: util-series (next to asn-lookup) was considered, but
  cybersecurity-series was chosen because the primary use case is IR/OSINT
  investigation
- ASN queries (RDAP autnum) are included in v0.1 — cheap to add via input
  detection plus the shared RDAP implementation. Differentiation from
  asn-lookup is clear: "attribution (offline)" vs "registration data and
  contacts (online)"
- CLI shape: rejected per-target subcommands (domain/ip/asn) in favor of a
  single `lookup` with auto-detection; the MCP side mirrors this with a
  single `lookup` tool so CLI and MCP behave identically
- Cache strategy: hybrid of abuse-lookup's per-query TTL and
  icloud-relay-lookup's ETag conditional GET. WHOIS data changes slowly, so
  the default TTL is 24h
- 2026-07-16 (review feedback): replaced the original "not IP, not ASN →
  treat as domain" rule with a domain syntax-validation gate; input that is
  valid as none of IP/ASN/domain is rejected before any network I/O.
  Rationale: prevents CRLF protocol injection into port 43, wasted rate
  limits, and cache-key pollution. IDN U-label conversion was initially left
  out of v0.1 scope due to the zero-dependency policy
- 2026-07-16 (follow-up decision): IDN support added to the plan. Instead of
  `x/net/idna`, an in-house RFC 3492 punycode encoder (~150 lines, keeping
  zero dependencies) lands in Phase 2. Simplified IDNA (lowercasing only;
  UTS#46/bidi out of scope), with Japanese-domain (.jp) investigation as the
  primary use case. Cache keys are unified on the A-label form
