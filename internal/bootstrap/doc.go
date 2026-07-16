// Package bootstrap resolves RDAP service endpoints from the IANA bootstrap
// registry (dns.json / ipv4.json / ipv6.json / asn.json under
// https://data.iana.org/rdap/), cached locally with ETag conditional GET
// (Phase 1). The files change rarely, so revalidation is cheap; a TLD absent
// from dns.json signals the port 43 WHOIS fallback.
package bootstrap
