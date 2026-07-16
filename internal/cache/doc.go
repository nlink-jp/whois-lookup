// Package cache stores per-query lookup results with a TTL (default 24h,
// Phase 1) under ~/.cache/whois-lookup/. WHOIS data changes slowly and
// registries rate-limit aggressively, so caching is mandatory etiquette, not
// an optimization. Keys use the canonical form (A-label domains, canonical
// IPs), writes are atomic (temp + rename), and freshness lives in the record
// rather than the file mtime.
package cache
