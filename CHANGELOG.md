# Changelog

All notable changes to whois-lookup are documented here.

## [Unreleased]

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
