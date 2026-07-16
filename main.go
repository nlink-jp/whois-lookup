// Command whois-lookup reports the registration data (registrar, dates,
// nameservers, abuse contact) of a domain, IP address, or AS number, as a CLI
// and (Phase 2) a local MCP server. RDAP-first (IANA bootstrap, structured
// JSON) with a port 43 WHOIS fallback for ccTLDs without RDAP. The
// registration-focused, credential-zero sibling of asn-lookup (attribution)
// and abuse-lookup (reputation).
package main

import (
	"os"

	"github.com/nlink-jp/whois-lookup/internal/app"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(app.Run(os.Args[1:], version))
}
