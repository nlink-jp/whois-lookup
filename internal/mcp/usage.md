# whois-lookup MCP server — operating manual

whois-lookup returns the **registration data** of a domain, IP address, or
AS number: registrar, creation/update/expiry dates, nameservers, status, and
abuse contact. Queries go to the official RDAP endpoints (resolved via the
IANA bootstrap registry) and fall back to raw port 43 WHOIS for ccTLDs
without RDAP (e.g. .jp). No credentials are needed; results are cached
locally (default TTL 24h), so repeated lookups are free and fast.

## Tools

### lookup

One query per call. The input type is auto-detected: an IP address
(v4/v6), an AS number (`AS13335` or bare digits), or a domain name.
IDN domains (e.g. `日本語.jp`) are converted to punycode in-house.

Arguments:

- `query` (string, required) — IP, domain, or AS number.
- `type` (string, optional) — `ip` | `domain` | `asn` to override detection
  (a bare number otherwise reads as an ASN).
- `raw` (boolean, optional) — include the raw registry payload: `raw`
  (RDAP JSON) or `raw_text` (WHOIS text).
- `refresh` (boolean, optional) — bypass the cache and re-fetch.

Result fields (empty fields are omitted): `query`, `query_ascii` (punycode
form when it differs), `type`, `source` (`rdap` | `whois`), `cached`,
`handle`, `name`, `registrar`, `created`, `updated`, `expires`,
`nameservers`, `status`, `range`, `country`, `abuse_contact` ({name,
email}), `raw`, `raw_text`.

Note: since GDPR, most registrant personal data is redacted by registries.
The reliably available fields are registrar, dates, nameservers, status,
and — for IP/ASN queries — the network name, range, country, and abuse
contact.

### cache_status

Reports the cache directory, query-entry count, TTL, and the IANA bootstrap
files' freshness. No arguments.

### get_usage

Returns this manual. No arguments.

## Errors

Tool errors are structured JSON: `{"code": "...", "message": "..."}`.

| code | meaning | recovery |
|------|---------|----------|
| `invalid_input` | The query is valid as none of IP / ASN / domain. Nothing was sent to the network. | Fix the query. Pass `type` if auto-detection picked wrongly. |
| `not_found` | The registry answered authoritatively that the object does not exist (RDAP 404 / WHOIS no match). | Not an outage — the object is unregistered. |
| `no_rdap_service` | No RDAP endpoint exists for this IP/ASN registry. | Rare; usually indicates a bootstrap problem. Retry with `refresh: true`. |
| `network_error` | A registry or IANA was unreachable, or answered abnormally. | Retry later; registries rate-limit aggressively, so avoid rapid retries — the cache exists for a reason. |
