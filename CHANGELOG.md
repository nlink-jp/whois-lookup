# Changelog

All notable changes to whois-lookup are documented here.

## [Unreleased]

### Fixed

- **Every MCP tool input schema is closed.** The schemas omitted
  `additionalProperties: false`, so a mistyped argument read as a legitimate one
  to any client that validates against them. Schemas are now built through a
  single `obj()` helper that sets the flag, and an arch test fails if a tool's
  schema omits it — org ADR-021 §10 requires the test as well as the flag,
  because a rule stated only in prose is re-decided by whoever adds the next
  tool. The server's own argument decoding is unchanged and still lenient: it
  does not use `DisallowUnknownFields`, so an unknown argument that reaches it
  is ignored rather than refused.

## [0.1.0] - 2026-07-16

Initial release.

### Added

- Phase 2 features: port 43 WHOIS fallback with referral chasing
  (iana → registry → registrar; raw-first with best-effort extraction
  including the JPRS bracketed form), in-house RFC 3492 punycode for IDN
  domains (`日本語.jp` → `xn--wgv71a119e.jp`, cache keys unified on the
  A-label form), `cache status|clear` subcommands, and the stdio MCP server
  (`lookup` / `cache_status` / `get_usage`, structured tool errors).

- Phase 1 core: `lookup` command with RDAP queries for domains, IPs, and
  ASNs — input classification with the pre-network validation gate, IANA
  bootstrap resolution with ETag conditional-GET caching (stale degrade on
  network failure), lenient RDAP normalization into the shared result
  schema, per-query TTL cache (default 24h), `--type/--json/--raw/
  --refresh/--timeout` flags, exit codes 0/1/2.
- Project scaffold: CLI dispatch skeleton (`lookup` / `cache` / `mcp` /
  `version` stubs with tests), package layout for the RDAP-first design,
  build/sign/notarize/brew tooling from the org templates, bilingual README
  and RFP.
