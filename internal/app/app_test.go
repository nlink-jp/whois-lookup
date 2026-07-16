package app

import (
	"strings"
	"testing"
)

func TestRunExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no args", nil, exitError},
		{"unknown command", []string{"frobnicate"}, exitError},
		{"version", []string{"version"}, exitOK},
		{"version long flag", []string{"--version"}, exitOK},
		{"version short flag", []string{"-v"}, exitOK},
		{"help", []string{"help"}, exitOK},
		{"help long flag", []string{"--help"}, exitOK},
		{"help short flag", []string{"-h"}, exitOK},
		{"lookup invalid input", []string{"lookup", "!!!"}, exitError},
		{"lookup missing arg", []string{"lookup"}, exitError},
		{"cache without subcommand", []string{"cache"}, exitError},
		{"mcp exits cleanly on closed stdin", []string{"mcp"}, exitOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Run(tt.args, "test"); got != tt.want {
				t.Errorf("Run(%v) = %d, want %d", tt.args, got, tt.want)
			}
		})
	}
}

func TestUsageListsCommands(t *testing.T) {
	var sb strings.Builder
	usage(&sb)
	out := sb.String()
	for _, want := range []string{"lookup", "cache status", "cache clear", "mcp", "version", "--type", "--json", "--raw", "--refresh"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage output missing %q", want)
		}
	}
}
