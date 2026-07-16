// Package whois implements the port 43 WHOIS fallback (Phase 2) for TLDs
// without RDAP: the raw "query + CRLF" protocol over TCP with referral
// chasing (whois.iana.org "refer:" → registry → thin-registry "Registrar
// WHOIS Server:"). The raw text is the primary result; a best-effort loose
// key:value extraction is attached — no full parser. Queries reach this
// package only after the query package's validation gate, so no CRLF or
// control characters can be smuggled into the protocol.
package whois
