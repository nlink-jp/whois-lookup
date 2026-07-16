// Package rdap implements the RDAP client (Phase 1): domain / ip / autnum
// queries over HTTPS returning structured JSON, normalized into the output
// schema (registrar, events, nameservers, status, abuse contact from vCard).
// Registry implementations vary in optional fields, so decoding is lenient
// and normalization happens here. The HTTP client is injected for tests.
package rdap
