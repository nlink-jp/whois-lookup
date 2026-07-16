// Package query classifies and validates lookup input (Phase 1). Detection
// order: netip.ParseAddr → IP; ^AS\d+$ (case-insensitive) → ASN; otherwise
// the input must pass RFC-compliant domain syntax validation (total ≤253,
// labels 1–63 LDH, at least one dot) or it is rejected before any network
// I/O — the safety gate that blocks CRLF/control-character injection into
// port 43, wasted rate limits, and cache-key pollution. Non-ASCII labels are
// converted to A-labels via the idn package (Phase 2) before validation.
package query
