package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/nlink-jp/whois-lookup/internal/config"
	"github.com/nlink-jp/whois-lookup/internal/engine"
	"github.com/nlink-jp/whois-lookup/internal/query"
	"github.com/nlink-jp/whois-lookup/internal/rdap"
)

// runLookup implements the lookup command against injected writers so tests
// can capture output.
func runLookup(args []string, version string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lookup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		typeHint = fs.String("type", "", "input type: ip, domain, or asn (default: auto-detect)")
		jsonOut  = fs.Bool("json", false, "JSON output")
		raw      = fs.Bool("raw", false, "include the raw RDAP response")
		refresh  = fs.Bool("refresh", false, "bypass the query cache and re-fetch")
		timeout  = fs.Duration("timeout", 0, "network timeout (e.g. 5s; default 10s)")
		cfgPath  = fs.String("config", "", "config file path")
	)
	fs.BoolVar(jsonOut, "j", false, "JSON output (shorthand)")
	fs.StringVar(cfgPath, "c", "", "config file path (shorthand)")

	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return exitError
	}
	if len(positionals) != 1 {
		fmt.Fprintln(stderr, "lookup: exactly one query (IP, domain, or AS number) is required")
		return exitError
	}

	cfg, err := config.Load(*cfgPath, *timeout)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	e := engine.New(cfg, version)
	res, err := e.Lookup(positionals[0], engine.Options{
		TypeHint: query.Type(*typeHint),
		Refresh:  *refresh,
		Raw:      *raw,
	})
	switch {
	case errors.Is(err, rdap.ErrNotFound):
		fmt.Fprintf(stderr, "%v\n", err)
		return exitNotFound
	case err != nil:
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}

	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitError
		}
		return exitOK
	}
	printText(stdout, res)
	return exitOK
}

// parseInterspersed parses fs while tolerating flags that appear after
// positional arguments (Go's flag package otherwise stops at the first
// non-flag). Validated queries never begin with '-', so there is no
// ambiguity.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positionals = append(positionals, args[0])
		args = args[1:]
	}
	return positionals, nil
}

// printText renders a Result as aligned key: value lines, skipping empty
// fields.
func printText(w io.Writer, res *rdap.Result) {
	line := func(k, v string) {
		if v != "" {
			fmt.Fprintf(w, "%-14s %s\n", k+":", v)
		}
	}
	line("query", res.Query)
	line("query_ascii", res.QueryASCII)
	line("type", res.Type)
	source := res.Source
	if res.Cached {
		source += " (cached)"
	}
	line("source", source)
	line("handle", res.Handle)
	line("name", res.Name)
	line("registrar", res.Registrar)
	line("created", res.Created)
	line("updated", res.Updated)
	line("expires", res.Expires)
	for _, ns := range res.Nameservers {
		line("nameserver", ns)
	}
	for _, st := range res.Status {
		line("status", st)
	}
	line("range", res.Range)
	line("country", res.Country)
	if c := res.AbuseContact; c != nil {
		v := c.Name
		if c.Email != "" {
			if v != "" {
				v += " "
			}
			v += "<" + c.Email + ">"
		}
		line("abuse", v)
	}
	if len(res.Raw) > 0 {
		fmt.Fprintf(w, "raw:\n%s\n", res.Raw)
	}
}
