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
  tool.

- `make check` is green again: `make lint` failed on 21 errcheck findings.
  Nine were `fmt.Fprint*` writes to the CLI's own stdout/stderr, now excluded
  in a new `.golangci.yml` with the reasoning recorded there — reporting a
  failed write to the stream that just failed is circular, and the exit code
  already carries the outcome. The other twelve were deliberate discards
  (reading a config file, closing response bodies and a WHOIS socket already
  read to EOF, the post-rename temp-file unlink, and test fixture servers whose
  failures surface as the client-side assertion) and are now written `_ =` with
  the reason beside each. None was a real unchecked error: the one write path
  that matters, `cache.writeAtomic`, already checks its temp file's `Close`
  before renaming.

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
