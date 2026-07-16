// Package app implements the whois-lookup command-line interface: subcommand
// dispatch plus the lookup / cache / mcp commands. Core logic lives in the
// query, bootstrap, rdap, whois, cache, config, and engine packages; this
// package is the thin I/O shell around them.
package app

import (
	"fmt"
	"io"
	"os"
)

// Exit codes. lookup is not a membership test, so unlike tor-exit-lookup's
// grep-style contract a not-found is a successful answer about a
// nonexistent object, distinct from failure.
const (
	exitOK       = 0 // lookup succeeded
	exitNotFound = 1 // the object does not exist (RDAP 404 / WHOIS no match)
	exitError    = 2 // usage / validation / network error
)

// Run dispatches a subcommand and returns a process exit code.
func Run(args []string, version string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return exitError
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "lookup":
		return runLookup(rest, version, os.Stdout, os.Stderr)
	case "cache":
		return cmdCache(rest)
	case "mcp":
		return cmdMCP(rest, version)
	case "version", "--version", "-v":
		fmt.Println("whois-lookup " + version)
		fmt.Println("Data: RDAP (IANA bootstrap, https://data.iana.org/rdap/) with port 43 WHOIS fallback.")
		return exitOK
	case "help", "-h", "--help":
		usage(os.Stdout)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage(os.Stderr)
		return exitError
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `whois-lookup — registration data for a domain, IP address, or AS number (RDAP-first)

Usage:
  whois-lookup <command> [flags] [args]

Commands:
  lookup <ip|domain|ASn>   Look up registration data (input type auto-detected)
  cache status             Show query-cache and bootstrap freshness
  cache clear              Clear the query cache
  mcp                      Run as a local MCP server (stdio)
  version                  Print the version

lookup flags:
  --type ip|domain|asn     Override input-type auto-detection
  -j, --json               JSON output (default: human-readable text)
  --raw                    Include the raw WHOIS text / raw RDAP response
  --refresh                Bypass the query cache and re-fetch
  --timeout <dur>          Network timeout (default 10s)

lookup exit codes:
  0  lookup succeeded
  1  the object does not exist (RDAP 404 / WHOIS no match)
  2  error (invalid input, network failure, ...)

Common flags:
  -c, --config <path>      Config file (default ~/.config/whois-lookup/config.toml)

Input that is valid as none of IP / ASN / domain is rejected before any
network I/O (safety gate). IDN (U-label) input is converted to punycode
A-labels in-house — no external dependencies.

Data: RDAP via the IANA bootstrap registry (https://data.iana.org/rdap/),
falling back to port 43 WHOIS (whois.iana.org referral chain) for TLDs
without RDAP. All endpoints are public; no credentials.
`)
}

// cmdCache will report / clear the query cache (Phase 2).
func cmdCache(_ []string) int {
	fmt.Fprintln(os.Stderr, "cache: not implemented yet (Phase 2)")
	return exitError
}

// cmdMCP will run the stdio MCP server (Phase 2).
func cmdMCP(_ []string, _ string) int {
	fmt.Fprintln(os.Stderr, "mcp: not implemented yet (Phase 2)")
	return exitError
}
