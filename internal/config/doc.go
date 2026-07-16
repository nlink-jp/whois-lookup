// Package config loads the sectioned-TOML subset config
// (~/.config/whois-lookup/config.toml) with WHOIS_LOOKUP_* env-var and flag
// resolution (Phase 1). No credentials — every endpoint is public. Settings:
// query-cache TTL, bootstrap revalidation interval, network timeout, cache
// directory.
package config
