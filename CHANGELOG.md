# Changelog

All notable changes to whois-lookup are documented here.

## [Unreleased]

### Fixed

- **`make verify-release` now fails closed.** Its last block chained unzip, the
  packaged binary's `--version` and `spctl` with `&&` and ended the whole chain
  in `|| true`, so a zip that did not unpack or a binary that did not run exited
  0 and the upload proceeded. Each step is now judged on its own, the packaged
  binary's `--version` must contain the tag being released, and only the
  informational `spctl` line may be ignored. Matches the org template
  (CONVENTIONS.md §Code Signing → Verifying a release).
- **The Linux archives no longer carry macOS file metadata.** macOS `tar` wrote
  each bundled file's extended attributes (`com.apple.provenance`, and a Dropbox
  attribute where the tree is synced) into the `.tar.gz` twice: as AppleDouble
  `._` members, which GNU tar extracts as stray `._<name>` files beside the real
  ones, and as `LIBARCHIVE.xattr.*` / `SCHILY.xattr.*` pax headers, which it
  reports as unknown keywords. `make package` now archives with
  `COPYFILE_DISABLE=1 tar --no-xattrs`; each setting stops one of the two.
  Archives already published still carry them; the files themselves are
  unaffected.

### Internal

- `make verify-release` also judges each Linux archive: no AppleDouble or other
  macOS metadata members — listed with `--options 'tar:!mac-ext'`, because a
  plain macOS listing folds `._` members away — no extended attributes as pax
  headers, and exactly the canonical binary, `README.md` and `LICENSE`, compared
  in the C locale.
- The Linux-archive check in `make verify-release` reads each archive's pax
  headers with Python's `tarfile` instead of grepping the decompressed stream,
  which also matched file text that names the keywords (a bundled CHANGELOG,
  for one).

## [0.2.0] - 2026-09-21

### Changed

- **An MCP tool call carrying an argument the tool does not declare now fails
  instead of being quietly ignored.** This is a deliberate behaviour change,
  required by org ADR-021 §4. Until now a misspelt argument was dropped and the
  call ran without it, and `refresh` is the one that matters: misspell it and a
  record from a cache with a 24-hour TTL comes back presented as freshly
  fetched — while an expiry date going stale is exactly what a caller passes
  `refresh` for. Every tool — including `get_usage` and `cache_status`, which
  take no arguments — now decodes with `DisallowUnknownFields` and refuses the
  call, naming the offending field:
  `{"code":"invalid_input","message":"arguments: json: unknown field \"refesh\""}`.

  A malformed argument object is refused for the same reason. The decode error
  used to be discarded along with the unknown field, so `{"query": 1}` ran as
  if no target had been named and came back with "provide 'query'", an answer
  that contradicted the request. It now reports the type mismatch.

  Nothing runs before the arguments decode, so a rejected call reaches neither
  a registry nor port 43. Omitting `arguments`, or sending `{}` or `null`,
  still means "no arguments" and is not an error. There is no compatibility
  shim: an argument name this server does not declare has never meant
  anything, so the only fix is to correct it.

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
